# 0001. The adapter verifies the event the extension signed

## Status

Accepted

## Context

NIP-07's `signEvent` "takes an event object, adds `id`, `pubkey` and `sig` and returns it". The object at `window.nostr` is planted by software the application did not ship, and which key it signs with is decided there: the user may have switched accounts in the extension. Trusting the returned event as-is looks reasonable, since the page asked for it, but an event signed by another key would be published under the user's apparent identity, and one whose `id` or `sig` does not verify would be refused later by every relay, far from the call that produced it.

A valid signature by the right key proves only who signed, not what. An extension that changes the kind, the content, the tags or the timestamp returns an event the caller never asked for, correctly signed, and the caller would publish it. NIP-07 lets the extension add `id`, `pubkey` and `sig` and nothing else, so any other difference is not what was asked for. A NIP-46 client signer faces the same boundary and makes the same checks.

What the adapter asked for is the template it sent: the output of `buildUnsignedEvent`, which gives an addressable kind with no `d` tag an added `["d", ""]`, not the object the caller passed.

## Decision

`signEvent` checks the extension's response in this order, and returns the event only when it passes every check:

1. It parses the response with `parseNostrEvent`, returning `sign-failed` when it is not a NIP-01 event.
2. When a key is expected — `getUserPubkey()`, else the pinned identity (ADR-0002) — an event whose `pubkey` differs returns `pubkey-mismatch` and calls `onPubkeyMismatch`.
3. It compares the event's `kind`, `content`, `created_at` and `tags` with the template sent, using `@innis/nostr-core`'s `checkSignedMatchesTemplate`, the one comparison every adapter for an outside signer shares. Each of the first three must equal the template's exactly. Tags are compared in order, element by element: the same number of tags, each with the same number of strings, equal at every position. Any difference returns that function's `sign-failed`.
4. It checks the event's `id` and signature, and one that does not verify returns `sign-failed`. The check is injectable (`verifyEventSignature`) and defaults to `@innis/nostr-core`'s.

The checks run cheapest first: the key, the fields, then the Schnorr verification. Only a returned event's key can become the pinned identity.

## Consequences

- An event returned by the signer can be published as it is: it is the event the caller asked for, signed by the user's key.
- An account switch is reported as `pubkey-mismatch` even when the extension also changed the event, so a host's logout or re-login flow still runs.
- An extension that adds to the events it signs, a `client` tag say, cannot sign through the adapter: whatever the event should carry goes in the template.
- Comparing tags as a set, or ignoring a trailing element, would let an extension reorder or extend them. Either changes the event's id, so the result is a different event; do not relax the comparison.
- A refused event costs no Schnorr verification. Every returned event costs one on the page; a host that needs it cheaper injects a faster verifier rather than turning the check off.
- A test stub must return the template's fields unchanged, and one that returns a fixture event with a placeholder signature must inject a verifier that accepts it.
- Shared decision: nostr-adrs ADR-0049.
