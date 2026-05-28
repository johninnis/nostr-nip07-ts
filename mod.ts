/**
 * NIP-07 `Signer` adapter for browser-extension key managers (Alby, nos2x, Flamingo, etc.).
 *
 * `@innis/nostr-nip07` wraps the `window.nostr` API exposed by NIP-07 extensions into a `Signer`
 * (from `@innis/nostr-core`) so application code never has to branch on signer kind. Behaviour
 * mirrors the canonical `Signer` contract: `getPublicKey` / `signEvent` throw on failure; NIP-04
 * / NIP-44 encrypt / decrypt return `Result<string, SignerError>`. The extension is treated as
 * an untrusted boundary — `signEvent` validates the response with `parseNostrEvent` from
 * `@innis/nostr-core` and throws `SigningError` on malformed output. Extension-side user
 * rejections are translated into `SignerRejectedError`; a pubkey mismatch between the user's
 * known identity and what the extension signs as throws `PubkeyMismatchError`.
 *
 * The returned signer carries `kind: "extension"` so consumers can discriminate it from
 * `createLocalSigner` (`kind: "local"`) or a NIP-46 client signer (`kind: "bunker"`) without
 * inspecting the implementation.
 *
 * @example
 * ```ts
 * import { createNip07Signer } from "@innis/nostr-nip07"
 *
 * const signer = createNip07Signer({
 *   getExtension: () => globalThis.window?.nostr ?? null,
 *   getUserPubkey: () => loggedInPubkey,
 *   onPubkeyMismatch: (expected, actual) => reportSecurityEvent({ expected, actual }),
 * })
 *
 * const signed = await signer.signEvent(unsignedEvent)
 * ```
 *
 * @module
 */

export * from "./src/nip07-signer.ts"
