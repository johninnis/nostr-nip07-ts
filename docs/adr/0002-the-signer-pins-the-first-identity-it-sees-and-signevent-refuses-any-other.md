# 0002. The signer pins the first identity it sees, and signEvent refuses any other

## Status

Accepted

## Context

Many extensions prompt the user on every `window.nostr.getPublicKey()` call, and the host usually knows the logged-in user's key already. Asking the extension each time would prompt repeatedly; re-reading the host's key on each `getPublicKey` would let the signer's reported identity drift silently with the session.

Extensions such as Alby and nos2x-fox let the user switch accounts mid-session, and NIP-07 gives no notice of it. A signer that checked signed events only against the host's key would, for a host that supplies none, publish as the new account while the application still believes it is the old one: a post, a reaction or a NIP-42/NIP-98 authorisation under a persona the user did not intend, publicly linking identities they meant to keep apart.

## Decision

- `getPublicKey` resolves once and keeps the result for the signer's lifetime: the host's `getUserPubkey()` when it returns a key, otherwise the extension's `getPublicKey()`, parsed with `parsePublicKey`.
- The first identity the signer sees is pinned: the key `getPublicKey` resolved, or, if `signEvent` runs first, the key of the first event it signs.
- `signEvent` compares every signed event's `pubkey` with `getUserPubkey()`, read afresh on each call, and when that returns `null`, with the pinned key. A difference returns `pubkey-mismatch` and fires `onPubkeyMismatch` (ADR-0001 then verifies the signature).

## Consequences

- The extension is asked for its key at most once, and not at all when the host already knows it.
- After a logout and a login as someone else, or a silent account switch in the extension, the next `signEvent` returns `pubkey-mismatch` before the wrong account's event leaves the adapter, whether or not the host supplies `getUserPubkey`. A host that changes user deliberately builds a new signer.
- NIP-04 and NIP-44 encryption cannot be guarded the same way: NIP-07 does not say which key the extension used, so after a switch a message is encrypted from the new account and one addressed to the old account will not decrypt. A host that cares supplies `getUserPubkey` and rebuilds the signer on a change of user.
- Making `getPublicKey` track `getUserPubkey()`, or skipping the check when the host supplies no key, removes the trip-wire; tests pin both.
