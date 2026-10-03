/**
 * Walkthrough of the main features of @innis/nostr-nip07.
 *
 * Run with: `deno run examples/walkthrough.ts` (no permissions required — the "extension" is a
 * stand-in for `window.nostr` backed by a local key, so everything runs locally). Each step
 * asserts what it shows.
 *
 * @module
 */

import { assert, assertEquals } from "@std/assert"
import {
  buildTextNote,
  createLocalSigner,
  generateSecretKey,
  parsePublicKey,
  verifyEventSignature,
} from "@innis/nostr-core"
import type { PublicKey, Result, Signer, SignerFailure } from "@innis/nostr-core"
import { createNip07Signer, isNostrExtension } from "../mod.ts"
import type { NostrExtension } from "../mod.ts"

const unwrap = async <T>(result: Promise<Result<T, SignerFailure>>): Promise<T> => {
  const settled = await result
  if (!settled.success) throw new Error(settled.error.message)
  return settled.value
}

const peerKey = (raw: string): PublicKey => {
  const key = parsePublicKey(raw)
  if (key === null) throw new Error(`not a public key: ${raw}`)
  return key
}

const extensionFor = (key: Signer): NostrExtension => ({
  getPublicKey: () => unwrap(key.getPublicKey()),
  signEvent: (event) => unwrap(key.signEvent(event)),
  nip44: {
    encrypt: (peer, text) => unwrap(key.nip44Encrypt(peerKey(peer), text)),
    decrypt: (peer, text) => unwrap(key.nip44Decrypt(peerKey(peer), text)),
  },
})

const alice = createLocalSigner(generateSecretKey())
const aliceKey = await unwrap(alice.getPublicKey())
const injected: unknown = extensionFor(alice)
assert(isNostrExtension(injected))
assertEquals(isNostrExtension({ getPublicKey: "not a function" }), false)

const signer = createNip07Signer({ getExtension: () => injected, getUserPubkey: () => aliceKey })
assertEquals(signer.kind, "extension")

const signed = await signer.signEvent(buildTextNote("signed by the extension", 1700000000))
assert(signed.success && verifyEventSignature(signed.value))

const ciphertext = await signer.nip44Encrypt(aliceKey, "note to self")
assert(ciphertext.success)
assertEquals(await signer.nip44Decrypt(aliceKey, ciphertext.value), { success: true, value: "note to self" })

const declining = createNip07Signer({
  getExtension: () => ({ ...extensionFor(alice), signEvent: () => Promise.reject(new Error("User rejected")) }),
  getUserPubkey: () => aliceKey,
})
const declined = await declining.signEvent(buildTextNote("no thanks", 1700000000))
assertEquals(declined.success ? null : declined.error.type, "rejected")

const absent = createNip07Signer({ getExtension: () => null, getUserPubkey: () => null })
const missing = await absent.signEvent(buildTextNote("nobody home", 1700000000))
assertEquals(missing.success ? null : missing.error.type, "no-signer")
