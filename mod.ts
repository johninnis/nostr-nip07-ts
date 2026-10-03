/**
 * NIP-07 `Signer` adapter for browser-extension key managers (Alby, nos2x, Flamingo, etc.).
 *
 * `@innis/nostr-nip07` wraps the `window.nostr` API exposed by NIP-07 extensions into a `Signer`
 * (from `@innis/nostr-core`) so application code never has to branch on signer kind. Behaviour
 * mirrors the canonical `Signer` contract: every method returns a `Result` whose failure is a
 * `SignerFailure`, and none throws. The extension is treated as an untrusted boundary —
 * `signEvent` validates the response with `parseNostrEvent` and verifies its signature with
 * `verifyEventSignature` from `@innis/nostr-core`, returning `sign-failed` on malformed or forged
 * output. An extension-side user rejection is returned as `rejected`, any other extension throw
 * as the method's failure mode carrying the extension's message, and a pubkey mismatch between
 * the user's known identity and what the extension signs as is returned as `pubkey-mismatch`.
 *
 * The returned signer carries `kind: "extension"` so consumers can discriminate it from
 * `createLocalSigner` (`kind: "local"`) or a NIP-46 client signer (`kind: "bunker"`) without
 * inspecting the implementation.
 *
 * @example
 * ```ts
 * import { createNip07Signer, isNostrExtension } from "@innis/nostr-nip07"
 * import type { NostrExtension } from "@innis/nostr-nip07"
 *
 * const injectedExtension = (): NostrExtension | null => {
 *   const candidate: unknown = Reflect.get(globalThis, "nostr")
 *   return isNostrExtension(candidate) ? candidate : null
 * }
 *
 * const signer = createNip07Signer({
 *   getExtension: injectedExtension,
 *   getUserPubkey: () => loggedInPubkey,
 *   onPubkeyMismatch: (expected, actual) => reportSecurityEvent({ expected, actual }),
 * })
 *
 * const signed = await signer.signEvent(unsignedEvent)
 * if (!signed.success && signed.error.type === "rejected") console.log("declined")
 * ```
 *
 * @module
 */

export * from "./src/nip07-signer-adapter.ts"
