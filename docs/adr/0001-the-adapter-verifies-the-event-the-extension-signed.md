# 0001. The adapter verifies the event the extension signed

## Status

Accepted

## Context

NIP-07's `signEvent` "takes an event object, adds `id`, `pubkey` and `sig` and returns it". The object at `window.nostr` is planted by software the application did not ship, and which key it signs with is decided there: the user may have switched accounts in the extension. Trusting the returned event as-is looks reasonable, since the page asked for it, but an event signed by another key would be published under the user's apparent identity, and one whose `id` or `sig` does not verify would be refused later by every relay, far from the call that produced it. The NIP-46 client signer faces the same boundary and checks the same two things.

## Decision

`signEvent` parses the response with `parseNostrEvent`, returning `sign-failed` when it is not a NIP-01 event. When `getUserPubkey` returns a key, an event whose `pubkey` differs returns `pubkey-mismatch` and calls `onPubkeyMismatch`. Then the event's `id` and signature are checked, and one that does not verify returns `sign-failed`. The check is injectable (`verifyEventSignature`) and defaults to `@innis/nostr-core`'s.

## Consequences

- An event returned by the signer can be published as it is.
- Every signature costs one Schnorr verification on the page; a host that needs it cheaper injects a faster verifier rather than turning the check off.
- A test stub that returns a fixture event with a placeholder signature must inject a verifier that accepts it.
