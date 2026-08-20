import { assertEquals, assertRejects } from "@std/assert"
import { parsePublicKey, PubkeyMismatchError, SignerRejectedError, SigningError } from "@innis/nostr-core"
import { buildEventFixture } from "@innis/nostr-core/testing"
import { createNip07Signer, isNostrExtension, type NostrExtension } from "../src/nip07-signer-adapter.ts"

const ALICE = parsePublicKey("a".repeat(64))
const BOB = parsePublicKey("b".repeat(64))
const CAROL = parsePublicKey("c".repeat(64))

const noExtension = (): NostrExtension | null => null
const provide = (ext: NostrExtension): () => NostrExtension | null => () => ext

const buildExtension = (overrides: Partial<NostrExtension> = {}): NostrExtension => ({
  getPublicKey: () => Promise.resolve(ALICE),
  signEvent: (event) => Promise.resolve(buildEventFixture({ ...event, pubkey: ALICE })),
  ...overrides,
})

Deno.test("getPublicKey - returns cached pubkey from getUserPubkey", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => BOB })

  const result = await signer.getPublicKey()

  assertEquals(result, BOB)
})

Deno.test("getPublicKey - caches the pubkey on subsequent calls", async () => {
  let callCount = 0
  const signer = createNip07Signer({
    getExtension: noExtension,
    getUserPubkey: () => {
      callCount++
      return BOB
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
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({ getPublicKey: () => Promise.resolve(CAROL) })),
    getUserPubkey: () => null,
  })

  const result = await signer.getPublicKey()

  assertEquals(result, CAROL)
})

Deno.test("nip44Decrypt - returns no-signer error when no extension is available", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => BOB })

  const result = await signer.nip44Decrypt(ALICE, "encrypted-text")

  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.tag, "no-signer")
})

Deno.test("nip44Encrypt - returns no-signer error when no extension is available", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => BOB })

  const result = await signer.nip44Encrypt(ALICE, "plaintext")

  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.tag, "no-signer")
})

Deno.test("nip04Encrypt - returns ok with extension's ciphertext", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      nip04: {
        encrypt: (_pubkey, plaintext) => Promise.resolve(`nip04:${plaintext}`),
        decrypt: () => Promise.reject(new Error("unused")),
      },
    })),
    getUserPubkey: () => ALICE,
  })

  const result = await signer.nip04Encrypt(BOB, "hello")
  assertEquals(result.success, true)
  if (result.success) assertEquals(result.value, "nip04:hello")
})

Deno.test("nip04Decrypt - returns ok with extension's plaintext", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      nip04: {
        encrypt: () => Promise.reject(new Error("unused")),
        decrypt: (_pubkey, ciphertext) => Promise.resolve(ciphertext.replace(/^nip04:/, "")),
      },
    })),
    getUserPubkey: () => ALICE,
  })

  const result = await signer.nip04Decrypt(BOB, "nip04:secret")
  assertEquals(result.success, true)
  if (result.success) assertEquals(result.value, "secret")
})

Deno.test("nip04Encrypt - returns no-signer error when extension does not implement nip04", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension()),
    getUserPubkey: () => ALICE,
  })

  const result = await signer.nip04Encrypt(BOB, "hi")
  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.tag, "no-signer")
})

Deno.test("signEvent - throws SigningError when extension returns a malformed signed event", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({ signEvent: () => Promise.resolve({ not: "a real event" }) })),
    getUserPubkey: () => ALICE,
  })

  await assertRejects(
    () => signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 }),
    SigningError,
    "invalid signed event",
  )
})

Deno.test("signEvent - throws SigningError when no extension is available", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => null })

  await assertRejects(
    () => signer.signEvent({ kind: 1, content: "test", tags: [], created_at: 1700000000 }),
    SigningError,
    "No NIP-07 extension found",
  )
})

Deno.test("signEvent - returns the extension's signed event when no mismatch", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension()),
    getUserPubkey: () => ALICE,
  })

  const signed = await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 })
  assertEquals(signed.pubkey, ALICE)
  assertEquals(signed.content, "hi")
})

Deno.test("signEvent - throws PubkeyMismatchError when extension signs as a different key", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      signEvent: (event) => Promise.resolve(buildEventFixture({ ...event, pubkey: BOB })),
    })),
    getUserPubkey: () => ALICE,
  })

  await assertRejects(
    () => signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 }),
    PubkeyMismatchError,
  )
})

Deno.test("signEvent - fires onPubkeyMismatch before throwing", async () => {
  const calls: Array<{ expected: string; actual: string }> = []
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      signEvent: (event) => Promise.resolve(buildEventFixture({ ...event, pubkey: BOB })),
    })),
    getUserPubkey: () => ALICE,
    onPubkeyMismatch: (e, a) => calls.push({ expected: e, actual: a }),
  })

  await assertRejects(
    () => signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 }),
    PubkeyMismatchError,
  )
  assertEquals(calls.length, 1)
  const [call] = calls
  if (!call) throw new Error("expected one onPubkeyMismatch call")
  assertEquals(call.expected, ALICE)
  assertEquals(call.actual, BOB)
})

Deno.test("signEvent - converts user-rejection errors to SignerRejectedError", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({ signEvent: () => Promise.reject(new Error("User rejected the request")) })),
    getUserPubkey: () => ALICE,
  })

  await assertRejects(
    () => signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 }),
    SignerRejectedError,
  )
})

Deno.test("nip44Encrypt - returns ok with extension's ciphertext", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      nip44: {
        encrypt: (_pubkey, plaintext) => Promise.resolve(`enc:${plaintext}`),
        decrypt: (_pubkey, ciphertext) => Promise.resolve(ciphertext.replace(/^enc:/, "")),
      },
    })),
    getUserPubkey: () => ALICE,
  })

  const result = await signer.nip44Encrypt(BOB, "hello")
  assertEquals(result.success, true)
  if (result.success) assertEquals(result.value, "enc:hello")
})

Deno.test("nip44Decrypt - returns ok with extension's plaintext", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      nip44: {
        encrypt: (_pubkey, plaintext) => Promise.resolve(`enc:${plaintext}`),
        decrypt: (_pubkey, ciphertext) => Promise.resolve(ciphertext.replace(/^enc:/, "")),
      },
    })),
    getUserPubkey: () => ALICE,
  })

  const result = await signer.nip44Decrypt(BOB, "enc:secret")
  assertEquals(result.success, true)
  if (result.success) assertEquals(result.value, "secret")
})

Deno.test("nip44Encrypt - throws SignerRejectedError when extension rejects", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      nip44: {
        encrypt: () => Promise.reject(new Error("User rejected the request")),
        decrypt: () => Promise.reject(new Error("nope")),
      },
    })),
    getUserPubkey: () => ALICE,
  })

  await assertRejects(
    () => signer.nip44Encrypt(BOB, "hello"),
    SignerRejectedError,
  )
})

Deno.test("nip44Decrypt - returns decrypt-failed when extension throws non-rejection error", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      nip44: {
        encrypt: () => Promise.resolve("ok"),
        decrypt: () => Promise.reject(new Error("ciphertext malformed")),
      },
    })),
    getUserPubkey: () => ALICE,
  })

  const result = await signer.nip44Decrypt(BOB, "junk")
  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.tag, "decrypt-failed")
})

Deno.test("nip44Encrypt - returns no-signer error when extension does not implement nip44", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension()),
    getUserPubkey: () => ALICE,
  })

  const result = await signer.nip44Encrypt(BOB, "hi")
  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.tag, "no-signer")
})

Deno.test("nip04Decrypt - throws SignerRejectedError when extension rejects", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      nip04: {
        encrypt: () => Promise.reject(new Error("unused")),
        decrypt: () => Promise.reject(new Error("User rejected the request")),
      },
    })),
    getUserPubkey: () => ALICE,
  })

  await assertRejects(() => signer.nip04Decrypt(BOB, "ciphertext"), SignerRejectedError)
})

Deno.test("nip04Encrypt - returns encrypt-failed when extension throws non-rejection error", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      nip04: {
        encrypt: () => Promise.reject(new Error("plaintext too long")),
        decrypt: () => Promise.reject(new Error("unused")),
      },
    })),
    getUserPubkey: () => ALICE,
  })

  const result = await signer.nip04Encrypt(BOB, "x".repeat(10_000))
  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.tag, "encrypt-failed")
})

Deno.test("getPublicKey - throws SigningError when extension returns malformed pubkey", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({ getPublicKey: () => Promise.resolve("not-a-hex-pubkey") })),
    getUserPubkey: () => null,
  })

  await assertRejects(() => signer.getPublicKey(), SigningError, "invalid public key")
})

Deno.test("isNostrExtension - accepts the mandatory NIP-07 surface", () => {
  assertEquals(isNostrExtension(buildExtension()), true)
})

Deno.test("isNostrExtension - rejects a value missing signEvent", () => {
  assertEquals(isNostrExtension({ getPublicKey: () => Promise.resolve("") }), false)
})

Deno.test("isNostrExtension - rejects members that are not functions", () => {
  assertEquals(isNostrExtension({ getPublicKey: "not a function", signEvent: () => Promise.resolve({}) }), false)
})

Deno.test("isNostrExtension - rejects non-objects", () => {
  assertEquals(isNostrExtension(null), false)
  assertEquals(isNostrExtension("nostr"), false)
})
