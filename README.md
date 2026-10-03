# @innis/nostr-nip07

[![CI](https://github.com/johninnis/nostr-nip07-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/johninnis/nostr-nip07-ts/actions/workflows/ci.yml)

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
import { createNip07Signer, isNostrExtension, type NostrExtension } from "@innis/nostr-nip07"

// NIP-07 extensions install themselves at `window.nostr`, which anything on the page can
// overwrite, so read it through the guard rather than trusting a global type declaration:
const injectedExtension = (): NostrExtension | null => {
  const candidate: unknown = Reflect.get(globalThis, "nostr")
  return isNostrExtension(candidate) ? candidate : null
}

const signer = createNip07Signer({
  getExtension: injectedExtension,
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

The package exports four symbols.

### `createNip07Signer(input: CreateNip07SignerInput): Signer`

Construct a `Signer` backed by a NIP-07 extension. `getPublicKey` is memoised after the first successful resolve — subsequent calls do not re-query the extension.

### `CreateNip07SignerInput`

```ts
interface CreateNip07SignerInput {
  readonly getExtension: () => NostrExtension | null
  readonly getUserPubkey: () => PublicKey | null
  readonly onPubkeyMismatch?: ((expected: PublicKey, actual: PublicKey) => void) | undefined
  readonly verifyEventSignature?: ((event: NostrEvent) => boolean) | undefined
}
```

- **`getExtension`** is invoked on every signer operation, not just at construction. This lets the page wait for `window.nostr` to be injected (extensions inject asynchronously after page load) and lets it react to the extension going away mid-session.
- **`getUserPubkey`** gates pubkey-mismatch detection. When it returns a non-null `PublicKey`, every signed event's pubkey is compared against it and a divergence returns a `pubkey-mismatch` `SignerFailure`. When it returns `null`, the event is compared with the first identity the signer saw instead (the key `getPublicKey` resolved, or the key of the first event signed), so an account switch inside the extension is still caught. NIP-04/NIP-44 encryption cannot be guarded this way, because NIP-07 does not say which key the extension used: a host that cares supplies `getUserPubkey` and builds a new signer on a change of user.
- **`onPubkeyMismatch`** fires when that failure is returned so callers can log, report telemetry, or trigger a logout flow in one place rather than at every `signEvent` call.
- **`verifyEventSignature`** checks the id and Schnorr signature of every event the extension signs. Defaults to `verifyEventSignature` from `@innis/nostr-core`.

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

`signEvent` is typed `Promise<unknown>` because the extension is an untrusted boundary: the adapter validates the response with `parseNostrEvent` from `@innis/nostr-core` before returning it. Stubs that resolve a real `NostrEvent` satisfy this signature unchanged — `NostrEvent` is assignable to `unknown`. Consumers writing tests against `createNip07Signer` satisfy this interface directly with a stub object — see `tests/nip07-signer-adapter.test.ts` for examples.

### `isNostrExtension(value: unknown): value is NostrExtension`

Whether a value has the mandatory NIP-07 surface (`getPublicKey` and `signEvent` functions). Read `window.nostr` through it, so that something that is not a signer reads as no extension instead of failing later inside one. The optional `nip04` / `nip44` sub-objects are checked per call by the adapter.

## Behaviour

### `getPublicKey`

Resolves once and freezes the result. Priority order on the resolving call: in-memory cache → `getUserPubkey()` (if non-null) → `ext.getPublicKey()`. The extension result is validated and branded as `PublicKey`; if validation fails, it returns a `public-key-failed` failure. Subsequent calls return the cached pubkey without re-querying anything.

Do not assume `getPublicKey()` will pick up a later change to `getUserPubkey()` — the cached value is a snapshot of the identity at the time the signer first resolved; a host that changes user builds a new signer (see `docs/adr/0002`).

### `signEvent`

Calls `ext.signEvent(event)` — a throw from the extension becomes a `rejected` or `sign-failed` failure (see [Failures](#failures)) — and validates the response with `parseNostrEvent` from `@innis/nostr-core` — the extension is an untrusted boundary, so a malformed response returns `sign-failed` rather than reaching the caller as a fake `NostrEvent`. `getUserPubkey()` is then called *fresh* (no cache) and, when non-null, compared against the signed event's pubkey; a divergence fires `onPubkeyMismatch?.(expected, actual)` and returns `pubkey-mismatch`. Finally the event's id and signature are verified, and one that does not verify returns `sign-failed`.

Because `signEvent` reads `getUserPubkey()` fresh, if the application's session pubkey changes after the signer is constructed (logout/login, extension silently switching accounts), the next `signEvent` catches the divergence before the wrong-account event leaves the boundary.

### `nip44Encrypt` / `nip44Decrypt` / `nip04Encrypt` / `nip04Decrypt`

Return `Promise<Result<string, SignerFailure>>`. The failure's `type` (`"no-signer"` | `"rejected"` | `"encrypt-failed"` | `"decrypt-failed"`) distinguishes the cause — extension missing or not implementing NIP-44 / NIP-04, the user declined, or the underlying call failed. NIP-04 is deprecated; the methods exist for legacy interop only.

## Failures

Every method returns `Promise<Result<…, SignerFailure>>` and none throws. `SignerFailure` is defined in `@innis/nostr-core` — the same one every other `@innis/*` signer returns; switch on its `type`. The extension is untrusted input, so nothing it throws crosses the adapter unconverted:

- **`no-signer`** — `getExtension()` returned `null`, or the extension does not implement the NIP a cipher method needs.
- **`rejected`** — the user clicked "deny": an extension throw whose message `isUserRejection` from `@innis/nostr-core` recognises, from every method.
- **`public-key-failed`** / **`sign-failed`** / **`encrypt-failed`** / **`decrypt-failed`** — the extension threw something that is not a rejection (the failure carries its message), or `getPublicKey` / `signEvent` answered with a malformed pubkey or event, or an event whose id or signature does not verify.
- **`pubkey-mismatch`** — `signEvent` produced an event whose pubkey didn't match `getUserPubkey()`.

## Testing

The signer is fully unit-testable without a browser. Pass a stub `NostrExtension` (or `null`) through `getExtension` and the rest of the dependency boundary is satisfied. The tests under `tests/nip07-signer-adapter.test.ts` cover every branch — extension presence / absence, NIP-04 / NIP-44 presence / absence, pubkey-mismatch detection, malformed extension responses, signature verification, user rejection, and the failure each method returns.

For integration tests that need a real signing path without a browser, use `createLocalSigner` from `@innis/nostr-core` with a generated keypair.

## License

MIT.
