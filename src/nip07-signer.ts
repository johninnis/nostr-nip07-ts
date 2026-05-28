import type { NostrEvent, PublicKey, Result, Signer, UnsignedEvent } from "@innis/nostr-core"
import {
  failure,
  isUserRejection,
  ok,
  parsePublicKey,
  PubkeyMismatchError,
  SignerError,
  SignerRejectedError,
  SigningError,
} from "@innis/nostr-core"

/**
 * The shape NIP-07 browser extensions expose at `window.nostr`. `getPublicKey` and `signEvent`
 * are mandatory; the encryption sub-objects are optional — older extensions ship only NIP-04,
 * newer ones may ship only NIP-44. Consumers writing tests against {@link createNip07Signer}
 * can satisfy this interface directly with a stub object.
 */
export interface NostrExtension {
  readonly getPublicKey: () => Promise<string>
  readonly signEvent: (event: UnsignedEvent) => Promise<NostrEvent>
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
 * - **User rejection** — detected via `isUserRejection` from `@innis/nostr-core` and thrown as
 *   `SignerRejectedError` from `signEvent`, `nip04*`, and `nip44*` alike. Rejection is a
 *   control-flow signal, not a recoverable cryptographic failure, so the `Result`-returning
 *   methods still throw rather than returning a failure tag.
 * - **Pubkey mismatch** (only when `getUserPubkey` returns non-null) — fires
 *   `onPubkeyMismatch?.(expected, actual)` then throws `PubkeyMismatchError` from `signEvent`.
 * - **Other extension errors** — `signEvent` re-throws untouched; NIP-04 / NIP-44 return
 *   `Result.failure(SignerError("decrypt-failed" | "encrypt-failed", …))`.
 */
export const createNip07Signer = (input: CreateNip07SignerInput): Signer => {
  const { getExtension, getUserPubkey, onPubkeyMismatch } = input
  let pubkeyCache: PublicKey | null = null

  const requireExtension = (): NostrExtension => {
    const ext = getExtension()
    if (!ext) throw new SigningError("No NIP-07 extension found")
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

  const callExt = async <T>(
    extract: (ext: NostrExtension) => Promise<T> | null,
    missingDetail: string,
    failureCode: "decrypt-failed" | "encrypt-failed",
  ): Promise<Result<T, SignerError>> => {
    const ext = getExtension()
    if (!ext) return failure(new SignerError("no-signer", "No NIP-07 extension found"))
    const promise = extract(ext)
    if (!promise) return failure(new SignerError("no-signer", missingDetail))
    try {
      return ok(await promise)
    } catch (err) {
      if (isUserRejection(err)) {
        throw new SignerRejectedError(err instanceof Error ? err.message : "user rejected")
      }
      return failure(new SignerError(failureCode, err instanceof Error ? err.message : String(err)))
    }
  }

  const nip44Decrypt = (pubkey: string, ciphertext: string): Promise<Result<string, SignerError>> =>
    callExt(
      (ext) => ext.nip44?.decrypt(pubkey, ciphertext) ?? null,
      "NIP-07 extension does not implement NIP-44",
      "decrypt-failed",
    )

  const nip44Encrypt = (pubkey: string, plaintext: string): Promise<Result<string, SignerError>> =>
    callExt(
      (ext) => ext.nip44?.encrypt(pubkey, plaintext) ?? null,
      "NIP-07 extension does not implement NIP-44",
      "encrypt-failed",
    )

  const nip04Decrypt = (pubkey: string, ciphertext: string): Promise<Result<string, SignerError>> =>
    callExt(
      (ext) => ext.nip04?.decrypt(pubkey, ciphertext) ?? null,
      "NIP-07 extension does not implement NIP-04",
      "decrypt-failed",
    )

  const nip04Encrypt = (pubkey: string, plaintext: string): Promise<Result<string, SignerError>> =>
    callExt(
      (ext) => ext.nip04?.encrypt(pubkey, plaintext) ?? null,
      "NIP-07 extension does not implement NIP-04",
      "encrypt-failed",
    )

  const signEvent = async (event: UnsignedEvent): Promise<NostrEvent> => {
    const ext = requireExtension()
    let signed: NostrEvent
    try {
      signed = await ext.signEvent(event)
    } catch (error) {
      if (isUserRejection(error)) throw new SignerRejectedError(error instanceof Error ? error.message : undefined)
      throw error
    }
    const expected = getUserPubkey()
    if (expected && signed.pubkey !== expected) {
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
