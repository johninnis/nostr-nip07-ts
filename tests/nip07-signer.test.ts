import { assertEquals, assertRejects } from "@std/assert"
import type { NostrEvent, UnsignedEvent } from "@innis/nostr-core"
import {
  parseEventId,
  parsePublicKey,
  parseSig,
  PubkeyMismatchError,
  SignerRejectedError,
  SigningError,
} from "@innis/nostr-core"
import type { NostrExtension } from "../src/nip07-signer.ts"
import { createNip07Signer } from "../src/nip07-signer.ts"

const noExtension = (): NostrExtension | null => null
const provide = (ext: NostrExtension): () => NostrExtension | null => () => ext

const makeSignedEvent = (template: UnsignedEvent, pubkey: string): NostrEvent => ({
  ...template,
  id: parseEventId("0".repeat(64)),
  pubkey: parsePublicKey(pubkey),
  sig: parseSig("f".repeat(128)),
})

Deno.test("getPublicKey - returns cached pubkey from getUserPubkey", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => parsePublicKey("b".repeat(64)) })

  const result = await signer.getPublicKey()

  assertEquals(result, "b".repeat(64))
})

Deno.test("getPublicKey - caches the pubkey on subsequent calls", async () => {
  let callCount = 0
  const signer = createNip07Signer({
    getExtension: noExtension,
    getUserPubkey: () => {
      callCount++
      return parsePublicKey("b".repeat(64))
    },
  })

  await signer.getPublicKey()
  await signer.getPublicKey()

  assertEquals(callCount, 1)
})

Deno.test("getPublicKey - throws SigningError when getUserPubkey returns null and no extension", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => null })

  await assertRejects(() => signer.getPublicKey(), SigningError, "No NIP-07 extension found")
})

Deno.test("getPublicKey - falls back to extension when getUserPubkey returns null", async () => {
  const fromExt = "c".repeat(64)
  const signer = createNip07Signer({
    getExtension: provide({
      getPublicKey: () => Promise.resolve(fromExt),
      signEvent: () => Promise.reject(new Error("unused")),
    }),
    getUserPubkey: () => null,
  })

  const result = await signer.getPublicKey()

  assertEquals(result, fromExt)
})

Deno.test("nip44Decrypt - returns no-signer error when no extension is available", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => parsePublicKey("b".repeat(64)) })

  const result = await signer.nip44Decrypt(parsePublicKey("a".repeat(64)), "encrypted-text")

  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.tag, "no-signer")
})

Deno.test("nip44Encrypt - returns no-signer error when no extension is available", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => parsePublicKey("b".repeat(64)) })

  const result = await signer.nip44Encrypt(parsePublicKey("a".repeat(64)), "plaintext")

  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.tag, "no-signer")
})

Deno.test("nip04Encrypt - returns ok with extension's ciphertext", async () => {
  const signer = createNip07Signer({
    getExtension: provide({
      getPublicKey: () => Promise.resolve("a".repeat(64)),
      signEvent: () => Promise.reject(new Error("unused")),
      nip04: {
        encrypt: (_pubkey, plaintext) => Promise.resolve(`nip04:${plaintext}`),
        decrypt: () => Promise.reject(new Error("unused")),
      },
    }),
    getUserPubkey: () => parsePublicKey("a".repeat(64)),
  })

  const result = await signer.nip04Encrypt(parsePublicKey("b".repeat(64)), "hello")
  assertEquals(result.success, true)
  if (result.success) assertEquals(result.value, "nip04:hello")
})

Deno.test("nip04Decrypt - returns ok with extension's plaintext", async () => {
  const signer = createNip07Signer({
    getExtension: provide({
      getPublicKey: () => Promise.resolve("a".repeat(64)),
      signEvent: () => Promise.reject(new Error("unused")),
      nip04: {
        encrypt: () => Promise.reject(new Error("unused")),
        decrypt: (_pubkey, ciphertext) => Promise.resolve(ciphertext.replace(/^nip04:/, "")),
      },
    }),
    getUserPubkey: () => parsePublicKey("a".repeat(64)),
  })

  const result = await signer.nip04Decrypt(parsePublicKey("b".repeat(64)), "nip04:secret")
  assertEquals(result.success, true)
  if (result.success) assertEquals(result.value, "secret")
})

Deno.test("nip04Encrypt - returns no-signer error when extension does not implement nip04", async () => {
  const signer = createNip07Signer({
    getExtension: provide({
      getPublicKey: () => Promise.resolve("a".repeat(64)),
      signEvent: () => Promise.reject(new Error("unused")),
    }),
    getUserPubkey: () => parsePublicKey("a".repeat(64)),
  })

  const result = await signer.nip04Encrypt(parsePublicKey("b".repeat(64)), "hi")
  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.tag, "no-signer")
})

Deno.test("signEvent - throws SigningError when extension returns a malformed signed event", async () => {
  const signer = createNip07Signer({
    getExtension: provide({
      getPublicKey: () => Promise.resolve("a".repeat(64)),
      signEvent: () => Promise.resolve({ not: "a real event" }),
    }),
    getUserPubkey: () => parsePublicKey("a".repeat(64)),
  })

  await assertRejects(
    () => signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 }),
    SigningError,
    "invalid signed event",
  )
})

Deno.test("signEvent - throws error when no extension is available", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => null })

  await assertRejects(
    () => signer.signEvent({ kind: 1, content: "test", tags: [], created_at: 1700000000 }),
    Error,
    "No NIP-07 extension found",
  )
})

Deno.test("signEvent - returns the extension's signed event when no mismatch", async () => {
  const userPk = "a".repeat(64)
  const signer = createNip07Signer({
    getExtension: provide({
      getPublicKey: () => Promise.resolve(userPk),
      signEvent: (event) => Promise.resolve(makeSignedEvent(event, userPk)),
    }),
    getUserPubkey: () => parsePublicKey(userPk),
  })

  const signed = await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 })
  assertEquals(signed.pubkey, userPk)
  assertEquals(signed.content, "hi")
})

Deno.test("signEvent - throws PubkeyMismatchError when extension signs as a different key", async () => {
  const expected = "a".repeat(64)
  const wrong = "b".repeat(64)
  const signer = createNip07Signer({
    getExtension: provide({
      getPublicKey: () => Promise.resolve(expected),
      signEvent: (event) => Promise.resolve(makeSignedEvent(event, wrong)),
    }),
    getUserPubkey: () => parsePublicKey(expected),
  })

  await assertRejects(
    () => signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 }),
    PubkeyMismatchError,
  )
})

Deno.test("signEvent - fires onPubkeyMismatch before throwing", async () => {
  const expected = "a".repeat(64)
  const wrong = "b".repeat(64)
  const calls: Array<{ expected: string; actual: string }> = []
  const signer = createNip07Signer({
    getExtension: provide({
      getPublicKey: () => Promise.resolve(expected),
      signEvent: (event) => Promise.resolve(makeSignedEvent(event, wrong)),
    }),
    getUserPubkey: () => parsePublicKey(expected),
    onPubkeyMismatch: (e, a) => calls.push({ expected: e, actual: a }),
  })

  await assertRejects(
    () => signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 }),
    PubkeyMismatchError,
  )
  assertEquals(calls.length, 1)
  const [call] = calls
  if (!call) throw new Error("expected one onPubkeyMismatch call")
  assertEquals(call.expected, expected)
  assertEquals(call.actual, wrong)
})

Deno.test("signEvent - converts user-rejection errors to SignerRejectedError", async () => {
  const signer = createNip07Signer({
    getExtension: provide({
      getPublicKey: () => Promise.resolve("a".repeat(64)),
      signEvent: () => Promise.reject(new Error("User rejected the request")),
    }),
    getUserPubkey: () => parsePublicKey("a".repeat(64)),
  })

  await assertRejects(
    () => signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 }),
    SignerRejectedError,
  )
})

Deno.test("nip44Encrypt - returns ok with extension's ciphertext", async () => {
  const signer = createNip07Signer({
    getExtension: provide({
      getPublicKey: () => Promise.resolve("a".repeat(64)),
      signEvent: (event) => Promise.resolve(makeSignedEvent(event, "a".repeat(64))),
      nip44: {
        encrypt: (_pk, plaintext) => Promise.resolve(`enc:${plaintext}`),
        decrypt: (_pk, ciphertext) => Promise.resolve(ciphertext.replace(/^enc:/, "")),
      },
    }),
    getUserPubkey: () => parsePublicKey("a".repeat(64)),
  })

  const result = await signer.nip44Encrypt(parsePublicKey("b".repeat(64)), "hello")
  assertEquals(result.success, true)
  if (result.success) assertEquals(result.value, "enc:hello")
})

Deno.test("nip44Decrypt - returns ok with extension's plaintext", async () => {
  const signer = createNip07Signer({
    getExtension: provide({
      getPublicKey: () => Promise.resolve("a".repeat(64)),
      signEvent: (event) => Promise.resolve(makeSignedEvent(event, "a".repeat(64))),
      nip44: {
        encrypt: (_pk, plaintext) => Promise.resolve(`enc:${plaintext}`),
        decrypt: (_pk, ciphertext) => Promise.resolve(ciphertext.replace(/^enc:/, "")),
      },
    }),
    getUserPubkey: () => parsePublicKey("a".repeat(64)),
  })

  const result = await signer.nip44Decrypt(parsePublicKey("b".repeat(64)), "enc:secret")
  assertEquals(result.success, true)
  if (result.success) assertEquals(result.value, "secret")
})

Deno.test("nip44Encrypt - throws SignerRejectedError when extension rejects", async () => {
  const signer = createNip07Signer({
    getExtension: provide({
      getPublicKey: () => Promise.resolve("a".repeat(64)),
      signEvent: (event) => Promise.resolve(makeSignedEvent(event, "a".repeat(64))),
      nip44: {
        encrypt: () => Promise.reject(new Error("User rejected the request")),
        decrypt: () => Promise.reject(new Error("nope")),
      },
    }),
    getUserPubkey: () => parsePublicKey("a".repeat(64)),
  })

  await assertRejects(
    () => signer.nip44Encrypt(parsePublicKey("b".repeat(64)), "hello"),
    SignerRejectedError,
  )
})

Deno.test("nip44Decrypt - returns decrypt-failed when extension throws non-rejection error", async () => {
  const signer = createNip07Signer({
    getExtension: provide({
      getPublicKey: () => Promise.resolve("a".repeat(64)),
      signEvent: (event) => Promise.resolve(makeSignedEvent(event, "a".repeat(64))),
      nip44: {
        encrypt: () => Promise.resolve("ok"),
        decrypt: () => Promise.reject(new Error("ciphertext malformed")),
      },
    }),
    getUserPubkey: () => parsePublicKey("a".repeat(64)),
  })

  const result = await signer.nip44Decrypt(parsePublicKey("b".repeat(64)), "junk")
  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.tag, "decrypt-failed")
})
