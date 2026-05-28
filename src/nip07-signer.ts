import type { NostrEvent, PublicKey, Result, Signer, SignerErrorTag, UnsignedEvent } from "@innis/nostr-core"
import {
  errorMessage,
  failure,
  isUserRejection,
  ok,
  parseNostrEvent,
  parsePublicKey,
  PubkeyMismatchError,
  SignerError,
  SignerRejectedError,
  SigningError,
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
 * Inputs to {@link createNip07Signer}.
 *
 * - **`getExtension`** is invoked on every signer operation, not just at construction. This lets
 *   the page wait for `window.nostr` to be injected (extensions inject asynchronously after
 *   page load) and lets it react to the extension going away mid-session.
 * - **`getUserPubkey`** gates pubkey-mismatch detection. When it returns a non-null `PublicKey`,
 *   every signed event's pubkey is compared against it and a divergence throws
 *   `PubkeyMismatchError`. Returning `null` skips the check and trusts whatever the extension
 *   produces — only appropriate before the user's identity is known.
 * - **`onPubkeyMismatch`** fires *before* `PubkeyMismatchError` is thrown so callers can log,
 *   report telemetry, or trigger a logout flow without wrapping every `signEvent` call in
 *   `try` / `catch`.
 */
export interface CreateNip07SignerInput {
  readonly getExtension: () => NostrExtension | null
  readonly getUserPubkey: () => PublicKey | null
  readonly onPubkeyMismatch?: (expected: PublicKey, actual: PublicKey) => void
}

const NIP_LABEL = { nip04: "NIP-04", nip44: "NIP-44" } as const

/**
 * Construct a `Signer` (from `@innis/nostr-core`) backed by a NIP-07 browser extension.
 *
 * The returned signer is frozen and carries `kind: "extension"`. `getPublicKey` is memoised
 * after the first successful resolve — subsequent calls return the cached value without
 * re-querying the extension. The cache is populated from {@link CreateNip07SignerInput.getUserPubkey}
 * when non-null, otherwise from `ext.getPublicKey()` (the result is validated and branded as
 * `PublicKey`).
 *
 * Error translation:
 *
 * - **No extension present** — `getPublicKey` and `signEvent` throw `SigningError`; NIP-04 /
 *   NIP-44 methods return `Result.failure(SignerError("no-signer", …))`.
 * - **Extension returned a malformed signed event** — `signEvent` throws `SigningError`. The
 *   extension is treated as untrusted; the response is validated with `parseNostrEvent` before
 *   being returned to the caller.
 * - **User rejection** — detected via `isUserRejection` from `@innis/nostr-core` and thrown as
 *   `SignerRejectedError` from `signEvent`, `nip04*`, and `nip44*` alike. Rejection is a
 *   control-flow signal, not a recoverable cryptographic failure, so the `Result`-returning
 *   methods still throw rather than returning a failure tag.
 * - **Pubkey mismatch** (only when `getUserPubkey` returns non-null) — fires
 *   `onPubkeyMismatch?.(expected, actual)` then throws `PubkeyMismatchError` from `signEvent`.
 * - **Other extension errors** — `signEvent` re-throws untouched; NIP-04 / NIP-44 return
 *   `Result.failure(SignerError("decrypt-failed" | "encrypt-failed", …))` with the original
 *   error preserved as `cause`.
 */
export const createNip07Signer = (input: CreateNip07SignerInput): Signer => {
  const { getExtension, getUserPubkey, onPubkeyMismatch } = input
  let pubkeyCache: PublicKey | null = null

  const requireExtension = (): NostrExtension => {
    const ext = getExtension()
    if (ext === null) throw new SigningError("No NIP-07 extension found")
    return ext
  }

  const getPublicKey = async (): Promise<PublicKey> => {
    if (pubkeyCache !== null) return pubkeyCache
    const fromCaller = getUserPubkey()
    if (fromCaller !== null) {
      pubkeyCache = fromCaller
      return pubkeyCache
    }
    const fromExt = await requireExtension().getPublicKey()
    pubkeyCache = parsePublicKey(fromExt)
    return pubkeyCache
  }

  const cryptoCall = (
    nip: "nip04" | "nip44",
    operation: "encrypt" | "decrypt",
  ): (peerPubkey: string, payload: string) => Promise<Result<string, SignerError>> => {
    const failureTag: SignerErrorTag = operation === "encrypt" ? "encrypt-failed" : "decrypt-failed"
    return async (peerPubkey, payload) => {
      const ext = getExtension()
      if (ext === null) return failure(new SignerError("no-signer", "No NIP-07 extension found"))
      const sub = ext[nip]
      if (sub === undefined) {
        return failure(new SignerError("no-signer", `NIP-07 extension does not implement ${NIP_LABEL[nip]}`))
      }
      try {
        return ok(await sub[operation](peerPubkey, payload))
      } catch (err) {
        if (isUserRejection(err)) throw new SignerRejectedError(errorMessage(err), err)
        return failure(new SignerError(failureTag, errorMessage(err), err))
      }
    }
  }

  const nip04Encrypt = cryptoCall("nip04", "encrypt")
  const nip04Decrypt = cryptoCall("nip04", "decrypt")
  const nip44Encrypt = cryptoCall("nip44", "encrypt")
  const nip44Decrypt = cryptoCall("nip44", "decrypt")

  const signEvent = async (event: UnsignedEvent): Promise<NostrEvent> => {
    const ext = requireExtension()
    let raw: unknown
    try {
      raw = await ext.signEvent(event)
    } catch (err) {
      if (isUserRejection(err)) throw new SignerRejectedError(errorMessage(err), err)
      throw err
    }
    const signed = parseNostrEvent(raw)
    if (signed === null) throw new SigningError("NIP-07 extension returned an invalid signed event")
    const expected = getUserPubkey()
    if (expected !== null && signed.pubkey !== expected) {
      onPubkeyMismatch?.(expected, signed.pubkey)
      throw new PubkeyMismatchError(expected, signed.pubkey)
    }
    return signed
  }

  return Object.freeze({
    kind: "extension",
    getPublicKey,
    nip04Decrypt,
    nip04Encrypt,
    nip44Decrypt,
    nip44Encrypt,
    signEvent,
  })
}
