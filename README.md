# @innis/nostr-nip07

A NIP-07 [`Signer`](https://jsr.io/@innis/nostr-core) adapter for browser-extension key managers — Alby, nos2x, Flamingo, and anything else that exposes the `window.nostr` API.

The whole package is one factory function. It wraps the extension's wire surface (`getPublicKey`, `signEvent`, optional `nip04` / `nip44` sub-objects) into the canonical `Signer` interface from `@innis/nostr-core`, so application code can be written against `Signer` and stay oblivious to whether it's talking to a NIP-07 extension, a `createLocalSigner`, or a NIP-46 client signer. The returned signer carries `kind: "extension"` for code that does need to discriminate.

## Install

```bash
deno add jsr:@innis/nostr-nip07
```

For Node or Bun:

```bash
npx jsr add @innis/nostr-nip07
```

## Quick start

```ts
import { createNip07Signer, type NostrExtension } from "@innis/nostr-nip07"

// NIP-07 extensions install themselves at `window.nostr`. The library does not augment
// the global `Window` type — declare it once in your own app so `globalThis.window.nostr`
// type-checks:
declare global {
  interface Window {
    nostr?: NostrExtension
  }
}

const signer = createNip07Signer({
  getExtension: () => globalThis.window?.nostr ?? null,
  getUserPubkey: () => loggedInPubkey, // PublicKey | null
  onPubkeyMismatch: (expected, actual) => {
    console.warn("extension is signing as a different account", { expected, actual })
  },
})

const pubkey = await signer.getPublicKey()
const signed = await signer.signEvent(unsignedEvent)

const ciphertext = await signer.nip44Encrypt(peerPubkey, "hi")
if (ciphertext.success) {
  console.log("encrypted:", ciphertext.value)
}
```

## Public surface

The package exports three symbols.

### `createNip07Signer(input: CreateNip07SignerInput): Signer`

Construct a `Signer` backed by a NIP-07 extension. `getPublicKey` is memoised after the first successful resolve — subsequent calls do not re-query the extension.

### `CreateNip07SignerInput`

```ts
interface CreateNip07SignerInput {
  readonly getExtension: () => NostrExtension | null
  readonly getUserPubkey: () => PublicKey | null
  readonly onPubkeyMismatch?: (expected: PublicKey, actual: PublicKey) => void
}
```

- **`getExtension`** is invoked on every signer operation, not just at construction. This lets the page wait for `window.nostr` to be injected (extensions inject asynchronously after page load) and lets it react to the extension going away mid-session.
- **`getUserPubkey`** gates pubkey-mismatch detection. When it returns a non-null `PublicKey`, every signed event's pubkey is compared against it and a divergence throws `PubkeyMismatchError`. Returning `null` skips the check and trusts whatever the extension produces — only appropriate before the user's identity is known.
- **`onPubkeyMismatch`** fires *before* `PubkeyMismatchError` is thrown so callers can log, report telemetry, or trigger a logout flow without wrapping every `signEvent` call in `try` / `catch`.

### `NostrExtension`

```ts
interface NostrExtension {
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
```

The shape NIP-07 extensions expose at `window.nostr`. `getPublicKey` and `signEvent` are mandatory; the encryption sub-objects are optional — older extensions ship only NIP-04, newer ones may ship only NIP-44.

`signEvent` is typed `Promise<unknown>` because the extension is an untrusted boundary: the adapter validates the response with `parseNostrEvent` from `@innis/nostr-core` before returning it. Stubs that resolve a real `NostrEvent` satisfy this signature unchanged — `NostrEvent` is assignable to `unknown`. Consumers writing tests against `createNip07Signer` satisfy this interface directly with a stub object — see `tests/nip07-signer.test.ts` for examples.

## Behaviour

### `getPublicKey`

Resolves once and freezes the result. Priority order on the resolving call: in-memory cache → `getUserPubkey()` (if non-null) → `ext.getPublicKey()`. The extension result is validated and branded as `PublicKey`; if validation fails, `SigningError` is thrown with the underlying `InvalidPublicKeyError` preserved as `cause`. Subsequent calls return the cached pubkey without re-querying anything.

The freeze is deliberate, and is one half of the mid-session identity-drift trip-wire (see `signEvent` below). Do not assume `getPublicKey()` will pick up a later change to `getUserPubkey()` — the cached value is a snapshot of the identity at the time the signer first resolved.

### `signEvent`

Calls `ext.signEvent(event)` and validates the response with `parseNostrEvent` from `@innis/nostr-core` — the extension is an untrusted boundary, so a malformed response throws `SigningError` rather than reaching the caller as a fake `NostrEvent`. `getUserPubkey()` is then called *fresh* (no cache) and, when non-null, compared against the signed event's pubkey; a divergence fires `onPubkeyMismatch?.(expected, actual)` and throws `PubkeyMismatchError`.

This is the second half of the trip-wire. Because `getPublicKey()` is frozen but `signEvent` reads `getUserPubkey()` fresh, if the application's session pubkey changes after the signer is constructed (logout/login, extension silently switching accounts), the next `signEvent` catches the divergence before the wrong-account event leaves the boundary.

### `nip44Encrypt` / `nip44Decrypt` / `nip04Encrypt` / `nip04Decrypt`

Return `Promise<Result<string, SignerError>>`. The failure tag (`"no-signer"` | `"encrypt-failed"` | `"decrypt-failed"`) distinguishes the cause — extension missing, NIP-44 / NIP-04 not implemented by the extension, or the underlying call failed. NIP-04 is deprecated; the methods exist for legacy interop only.

User rejection is the exception: it is thrown as `SignerRejectedError` rather than returned as a failure. Rejection is a control-flow signal (the user clicked "deny"), not a recoverable cryptographic failure, so it propagates through the same channel as `signEvent`'s rejection.

## Errors

All error classes are defined in `@innis/nostr-core` — the same ones every other `@innis/*` signer throws. Import them from `@innis/nostr-core` to `instanceof`-check or pattern-match on `.tag`.

- **`SigningError`** — `getPublicKey` / `signEvent` invoked while `getExtension()` returns `null`, or `signEvent` received a malformed response from the extension.
- **`SignerRejectedError`** — user clicked "deny" in the extension popup. Detected via `isUserRejection` from `@innis/nostr-core` (heuristic match on the extension's error message).
- **`PubkeyMismatchError`** — `signEvent` produced an event whose pubkey didn't match `getUserPubkey()`.
- **`SignerError("no-signer" | "encrypt-failed" | "decrypt-failed", …)`** — wrapped in `Result.failure` by `nip04*` / `nip44*` for non-rejection failures.

Other errors from the extension propagate untouched.

## Testing

The signer is fully unit-testable without a browser. Pass a stub `NostrExtension` (or `null`) through `getExtension` and the rest of the dependency boundary is satisfied. The tests under `tests/nip07-signer.test.ts` cover every branch — extension presence / absence, NIP-04 / NIP-44 presence / absence, pubkey-mismatch detection, malformed extension responses, user rejection, and the encrypt / decrypt result-vs-throw split.

For integration tests that need a real signing path without a browser, use `createLocalSigner` from `@innis/nostr-core` with a generated keypair.

## License

MIT.
