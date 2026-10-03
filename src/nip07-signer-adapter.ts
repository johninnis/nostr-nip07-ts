import type { NostrEvent, PublicKey, Result, Signer, SignerFailure, UnsignedEvent } from "@innis/nostr-core"
import {
  buildUnsignedEvent,
  checkPubkeyMatches,
  failure,
  isUserRejection,
  ok,
  parseNostrEvent,
  parsePublicKey,
  verifyEventSignature as defaultVerifyEventSignature,
} from "@innis/nostr-core"

/**
 * The shape NIP-07 browser extensions expose at `window.nostr`. `getPublicKey` and `signEvent`
 * are mandatory; the encryption sub-objects are optional — older extensions ship only NIP-04,
 * newer ones may ship only NIP-44.
 *
 * `signEvent` is typed `Promise<unknown>` because the extension is an untrusted boundary: the
 * adapter validates the response with `parseNostrEvent` from `@innis/nostr-core` before
 * returning it. Stubs that resolve a real `NostrEvent` satisfy this signature unchanged
 * (`NostrEvent` is assignable to `unknown`).
 */
export interface NostrExtension {
  readonly getPublicKey: () => Promise<string>
  readonly signEvent: (event: UnsignedEvent) => Promise<unknown>
  readonly nip04?: {
    readonly decrypt: (pubkey: string, ciphertext: string) => Promise<string>
    readonly encrypt: (pubkey: string, plaintext: string) => Promise<string>
  }
  readonly nip44?: {
    readonly decrypt: (pubkey: string, ciphertext: string) => Promise<string>
    readonly encrypt: (pubkey: string, plaintext: string) => Promise<string>
  }
}

/**
 * Whether an unknown value is shaped like a {@linkcode NostrExtension}.
 *
 * `window.nostr` is planted by software the application did not ship — an extension's
 * content script, or anything else running on the page — so what is found there should be
 * read through this guard rather than trusted: something that is not a signer reads as no
 * extension instead of failing later inside one. Only the mandatory surface is checked;
 * the optional encryption sub-objects are validated per call by the adapter.
 */
export const isNostrExtension = (value: unknown): value is NostrExtension =>
  typeof value === "object" && value !== null &&
  "getPublicKey" in value && typeof value.getPublicKey === "function" &&
  "signEvent" in value && typeof value.signEvent === "function"

/**
 * Inputs to {@link createNip07Signer}.
 *
 * - **`getExtension`** is invoked on every signer operation, not just at construction. This lets
 *   the page wait for `window.nostr` to be injected (extensions inject asynchronously after
 *   page load) and lets it react to the extension going away mid-session.
 * - **`getUserPubkey`** is the host's view of the signed-in user. When it returns a non-null
 *   `PublicKey`, every signed event's pubkey is compared against it and a divergence returns a
 *   `pubkey-mismatch` `SignerFailure`. When it returns `null`, the event is compared against the
 *   first identity the signer saw instead — the key `getPublicKey` resolved, or the key of the
 *   first event signed — so an account switch inside the extension is still caught.
 * - **`onPubkeyMismatch`** fires when that failure is returned so callers can log, report
 *   telemetry, or trigger a logout flow in one place rather than at every `signEvent` call.
 * - **`verifyEventSignature`** checks the id and Schnorr signature of every event the extension
 *   signs. Defaults to the core `verifyEventSignature`.
 */
export interface CreateNip07SignerInput {
  readonly getExtension: () => NostrExtension | null
  readonly getUserPubkey: () => PublicKey | null
  readonly verifyEventSignature?: ((event: NostrEvent) => boolean) | undefined
  readonly onPubkeyMismatch?: ((expected: PublicKey, actual: PublicKey) => void) | undefined
}

const NIP_LABEL = { nip04: "NIP-04", nip44: "NIP-44" } as const

const NO_EXTENSION: SignerFailure = { type: "no-signer", message: "No NIP-07 extension found" }

const callExtension = async <T>(
  call: () => Promise<T>,
  failureType: SignerFailure["type"],
): Promise<Result<T, SignerFailure>> => {
  try {
    return ok(await call())
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return failure({ type: isUserRejection(message) ? "rejected" : failureType, message })
  }
}

/**
 * Construct a `Signer` (from `@innis/nostr-core`) backed by a NIP-07 browser extension.
 *
 * The returned signer carries `kind: "extension"`.
 *
 * **Pubkey caching is deliberate, and is the trip-wire that catches mid-session identity drift.**
 * `getPublicKey` resolves once and freezes the result. Priority order on the resolving call:
 * in-memory cache → {@link CreateNip07SignerInput.getUserPubkey} (if non-null) → `ext.getPublicKey()`
 * (validated and branded as `PublicKey`). Subsequent calls return the frozen value without
 * re-querying anything. `signEvent`, by contrast, compares each signed event's pubkey with
 * `getUserPubkey()`, read fresh, or when that is `null` with the first identity the signer saw —
 * so after a logout and login as someone else, or the extension silently switching accounts, the
 * next `signEvent` fires `onPubkeyMismatch` and returns a `pubkey-mismatch` failure before the
 * wrong-account event leaves the boundary (ADR-0002).
 *
 * Failure translation — the extension is untrusted input, so nothing it throws or returns
 * crosses this boundary unconverted, and no method throws on its account. Every failure is a returned
 * `Failure(SignerFailure)`. The one throw is the caller's own: a template that is not a NIP-01 event
 * is refused by `buildUnsignedEvent` before the extension is asked, and `signEvent` rejects with
 * `InvalidArgumentError`, as every `Signer` does.
 *
 * - **No extension present** — `no-signer` from every method; the NIP-04 / NIP-44 methods also
 *   return `no-signer` when the extension does not implement that NIP.
 * - **User rejection** — any extension throw whose message `isUserRejection` from
 *   `@innis/nostr-core` recognises is `rejected`, from every method.
 * - **Any other extension throw** — `public-key-failed`, `sign-failed`, `encrypt-failed` or
 *   `decrypt-failed` by method, carrying the extension's message.
 * - **Extension returned a malformed pubkey or signed event** — `public-key-failed` /
 *   `sign-failed`. `getPublicKey`'s response is validated with `parsePublicKey`, `signEvent`'s
 *   with `parseNostrEvent` and then, after the pubkey check, `verifyEventSignature` (ADR-0001).
 * - **Pubkey mismatch** (against `getUserPubkey()`, else the first identity the signer saw) —
 *   `signEvent` fires `onPubkeyMismatch?.(expected, actual)` and returns `pubkey-mismatch`.
 */
export const createNip07Signer = (input: CreateNip07SignerInput): Signer => {
  const { getExtension, getUserPubkey, onPubkeyMismatch, verifyEventSignature = defaultVerifyEventSignature } = input
  // Deliberate: the first identity seen is pinned, and signEvent checks getUserPubkey fresh, else the pin — see ADR-0002
  let pubkeyCache: PublicKey | null = null

  const getPublicKey = async (): Promise<Result<PublicKey, SignerFailure>> => {
    if (pubkeyCache !== null) return ok(pubkeyCache)
    const fromCaller = getUserPubkey()
    if (fromCaller !== null) {
      pubkeyCache = fromCaller
      return ok(fromCaller)
    }
    const ext = getExtension()
    if (ext === null) return failure(NO_EXTENSION)
    const raw = await callExtension(() => ext.getPublicKey(), "public-key-failed")
    if (!raw.success) return raw
    const parsed = parsePublicKey(raw.value)
    if (parsed === null) {
      return failure({ type: "public-key-failed", message: "NIP-07 extension returned an invalid public key" })
    }
    pubkeyCache = parsed
    return ok(parsed)
  }

  const cryptoCall = (
    nip: "nip04" | "nip44",
    operation: "encrypt" | "decrypt",
  ): Signer["nip04Encrypt"] => {
    const failureType: SignerFailure["type"] = operation === "encrypt" ? "encrypt-failed" : "decrypt-failed"
    return (peerPubkey, payload) => {
      const ext = getExtension()
      if (ext === null) return Promise.resolve(failure(NO_EXTENSION))
      const sub = ext[nip]
      if (sub === undefined) {
        return Promise.resolve(
          failure({ type: "no-signer", message: `NIP-07 extension does not implement ${NIP_LABEL[nip]}` }),
        )
      }
      return callExtension(() => sub[operation](peerPubkey, payload), failureType)
    }
  }

  const signEvent = async (event: UnsignedEvent): Promise<Result<NostrEvent, SignerFailure>> => {
    const template = buildUnsignedEvent(event)
    const ext = getExtension()
    if (ext === null) return failure(NO_EXTENSION)
    const raw = await callExtension(() => ext.signEvent(template), "sign-failed")
    if (!raw.success) return raw
    const signed = parseNostrEvent(raw.value)
    if (signed === null) {
      return failure({ type: "sign-failed", message: "NIP-07 extension returned an invalid signed event" })
    }
    const expected = getUserPubkey() ?? pubkeyCache
    const mismatch = checkPubkeyMatches(expected, signed.pubkey)
    if (mismatch !== null && expected !== null) {
      onPubkeyMismatch?.(expected, signed.pubkey)
      return failure(mismatch)
    }
    if (!verifyEventSignature(signed)) {
      return failure({ type: "sign-failed", message: "NIP-07 extension returned an event with an invalid signature" })
    }
    pubkeyCache ??= signed.pubkey
    return ok(signed)
  }

  return {
    kind: "extension",
    getPublicKey,
    signEvent,
    nip04Encrypt: cryptoCall("nip04", "encrypt"),
    nip04Decrypt: cryptoCall("nip04", "decrypt"),
    nip44Encrypt: cryptoCall("nip44", "encrypt"),
    nip44Decrypt: cryptoCall("nip44", "decrypt"),
  }
}
