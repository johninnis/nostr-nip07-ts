import { assertEquals, assertRejects } from "@std/assert"
import {
  buildTextNote,
  createLocalSigner,
  failure,
  generateSecretKey,
  InvalidArgumentError,
  ok,
} from "@innis/nostr-core"
import { buildEventFixture } from "@innis/nostr-core/testing"
import { createNip07Signer, isNostrExtension } from "../src/nip07-signer-adapter.ts"
import {
  acceptAnySignature,
  ALICE,
  BOB,
  buildExtension,
  CAROL,
  noExtension,
  provide,
} from "./support/fake-extension.ts"

Deno.test("getPublicKey - returns cached pubkey from getUserPubkey", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => BOB })

  const result = await signer.getPublicKey()

  assertEquals(result, ok(BOB))
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

Deno.test("getPublicKey - returns no-signer when getUserPubkey returns null and no extension", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => null })

  assertEquals(await signer.getPublicKey(), failure({ type: "no-signer", message: "No NIP-07 extension found" }))
})

Deno.test("getPublicKey - falls back to extension when getUserPubkey returns null", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({ getPublicKey: () => Promise.resolve(CAROL) })),
    getUserPubkey: () => null,
  })

  const result = await signer.getPublicKey()

  assertEquals(result, ok(CAROL))
})

Deno.test("nip44Decrypt - returns a no-signer failure when no extension is available", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => BOB })

  const result = await signer.nip44Decrypt(ALICE, "encrypted-text")

  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.type, "no-signer")
})

Deno.test("nip44Encrypt - returns a no-signer failure when no extension is available", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => BOB })

  const result = await signer.nip44Encrypt(ALICE, "plaintext")

  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.type, "no-signer")
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

Deno.test("nip04Encrypt - returns a no-signer failure when extension does not implement nip04", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension()),
    getUserPubkey: () => ALICE,
  })

  const result = await signer.nip04Encrypt(BOB, "hi")
  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.type, "no-signer")
})

Deno.test("signEvent - returns sign-failed when extension returns a malformed signed event", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({ signEvent: () => Promise.resolve({ not: "a real event" }) })),
    getUserPubkey: () => ALICE,
  })

  assertEquals(
    await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 }),
    failure({ type: "sign-failed", message: "NIP-07 extension returned an invalid signed event" }),
  )
})

Deno.test("signEvent - returns no-signer when no extension is available", async () => {
  const signer = createNip07Signer({ getExtension: noExtension, getUserPubkey: () => null })

  assertEquals(
    await signer.signEvent({ kind: 1, content: "test", tags: [], created_at: 1700000000 }),
    failure({ type: "no-signer", message: "No NIP-07 extension found" }),
  )
})

Deno.test("signEvent - returns the extension's signed event when no mismatch", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension()),
    getUserPubkey: () => ALICE,
    verifyEventSignature: acceptAnySignature,
  })

  const signed = await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 })
  assertEquals(signed.success && signed.value.pubkey, ALICE)
  assertEquals(signed.success && signed.value.content, "hi")
})

Deno.test("signEvent - returns pubkey-mismatch when extension signs as a different key", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      signEvent: (event) => Promise.resolve(buildEventFixture({ ...event, pubkey: BOB })),
    })),
    getUserPubkey: () => ALICE,
  })

  const result = await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 })
  assertEquals(!result.success && result.error.type, "pubkey-mismatch")
})

Deno.test("signEvent - fires onPubkeyMismatch when returning pubkey-mismatch", async () => {
  const calls: Array<{ expected: string; actual: string }> = []
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      signEvent: (event) => Promise.resolve(buildEventFixture({ ...event, pubkey: BOB })),
    })),
    getUserPubkey: () => ALICE,
    onPubkeyMismatch: (e, a) => calls.push({ expected: e, actual: a }),
  })

  await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 })
  assertEquals(calls.length, 1)
  const [call] = calls
  if (!call) throw new Error("expected one onPubkeyMismatch call")
  assertEquals(call.expected, ALICE)
  assertEquals(call.actual, BOB)
})

Deno.test("signEvent - returns rejected when the extension throws a user rejection", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({ signEvent: () => Promise.reject(new Error("User rejected the request")) })),
    getUserPubkey: () => ALICE,
  })

  assertEquals(
    await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 }),
    failure({ type: "rejected", message: "User rejected the request" }),
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

Deno.test("nip44Encrypt - returns rejected when extension rejects", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      nip44: {
        encrypt: () => Promise.reject(new Error("User rejected the request")),
        decrypt: () => Promise.reject(new Error("nope")),
      },
    })),
    getUserPubkey: () => ALICE,
  })

  assertEquals(
    await signer.nip44Encrypt(BOB, "hello"),
    failure({ type: "rejected", message: "User rejected the request" }),
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
  if (!result.success) assertEquals(result.error.type, "decrypt-failed")
})

Deno.test("nip44Encrypt - returns a no-signer failure when extension does not implement nip44", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension()),
    getUserPubkey: () => ALICE,
  })

  const result = await signer.nip44Encrypt(BOB, "hi")
  assertEquals(result.success, false)
  if (!result.success) assertEquals(result.error.type, "no-signer")
})

Deno.test("nip04Decrypt - returns rejected when extension rejects", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      nip04: {
        encrypt: () => Promise.reject(new Error("unused")),
        decrypt: () => Promise.reject(new Error("User rejected the request")),
      },
    })),
    getUserPubkey: () => ALICE,
  })

  assertEquals(
    await signer.nip04Decrypt(BOB, "ciphertext"),
    failure({ type: "rejected", message: "User rejected the request" }),
  )
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
  if (!result.success) assertEquals(result.error.type, "encrypt-failed")
})

Deno.test("getPublicKey - returns public-key-failed when extension returns malformed pubkey", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({ getPublicKey: () => Promise.resolve("not-a-hex-pubkey") })),
    getUserPubkey: () => null,
  })

  assertEquals(
    await signer.getPublicKey(),
    failure({ type: "public-key-failed", message: "NIP-07 extension returned an invalid public key" }),
  )
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

Deno.test("signEvent - returns sign-failed carrying the message of a non-rejection extension error", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({ signEvent: () => Promise.reject(new Error("wallet locked")) })),
    getUserPubkey: () => ALICE,
  })

  assertEquals(
    await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 }),
    failure({ type: "sign-failed", message: "wallet locked" }),
  )
})

Deno.test("signEvent - returns sign-failed for a synchronous extension throw", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      signEvent: () => {
        throw new Error("extension crashed")
      },
    })),
    getUserPubkey: () => ALICE,
  })

  assertEquals(
    await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 }),
    failure({ type: "sign-failed", message: "extension crashed" }),
  )
})

Deno.test("getPublicKey - returns public-key-failed carrying the message of a non-rejection extension error", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({ getPublicKey: () => Promise.reject(new Error("wallet locked")) })),
    getUserPubkey: () => null,
  })

  assertEquals(await signer.getPublicKey(), failure({ type: "public-key-failed", message: "wallet locked" }))
})

Deno.test("getPublicKey - returns rejected when the extension throws a user rejection", async () => {
  const signer = createNip07Signer({
    getExtension: provide(
      buildExtension({ getPublicKey: () => Promise.reject(new Error("User rejected the request")) }),
    ),
    getUserPubkey: () => null,
  })

  assertEquals(await signer.getPublicKey(), failure({ type: "rejected", message: "User rejected the request" }))
})

Deno.test("nip44Decrypt - returns the extension's message on a non-rejection throw", async () => {
  const original = new Error("ciphertext malformed")
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      nip44: {
        encrypt: () => Promise.resolve("ok"),
        decrypt: () => Promise.reject(original),
      },
    })),
    getUserPubkey: () => ALICE,
  })

  const result = await signer.nip44Decrypt(BOB, "junk")
  assertEquals(result.success, false)
  if (result.success) return
  assertEquals(result.error, { type: "decrypt-failed", message: "ciphertext malformed" })
})

Deno.test("nip44Encrypt - returns encrypt-failed rather than throwing when the extension throws synchronously", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      nip44: {
        encrypt: () => {
          throw new TypeError("not ready")
        },
        decrypt: () => Promise.resolve("unused"),
      },
    })),
    getUserPubkey: () => ALICE,
  })

  const result = await signer.nip44Encrypt(BOB, "hello")
  assertEquals(result.success, false)
  if (result.success) return
  assertEquals(result.error, { type: "encrypt-failed", message: "not ready" })
})

Deno.test("signEvent - rejects with InvalidArgumentError for a template that is not a NIP-01 event, asking no extension", async () => {
  let asked = 0
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      signEvent: (event) => {
        asked++
        return Promise.resolve(buildEventFixture({ ...event, pubkey: ALICE }))
      },
    })),
    getUserPubkey: () => null,
  })
  for (const template of [{ kind: 70000, created_at: 1 }, { kind: 1, created_at: 1.5 }, { kind: 1, created_at: -5 }]) {
    await assertRejects(() => signer.signEvent({ ...template, content: "", tags: [] }), InvalidArgumentError)
  }
  assertEquals(asked, 0)
})

Deno.test("signEvent - returns sign-failed when the extension's event does not verify", async () => {
  const signer = createNip07Signer({
    getExtension: provide(buildExtension()),
    getUserPubkey: () => ALICE,
    verifyEventSignature: () => false,
  })

  const result = await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 })

  assertEquals(
    result,
    failure({ type: "sign-failed", message: "NIP-07 extension returned an event with an invalid signature" }),
  )
})

Deno.test("signEvent - verifies with the core verifier by default, refusing a fixture signature", async () => {
  const signer = createNip07Signer({ getExtension: provide(buildExtension()), getUserPubkey: () => ALICE })

  const result = await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 })

  assertEquals(!result.success && result.error.type, "sign-failed")
})

Deno.test("signEvent - accepts an event really signed by the user's key under the default verifier", async () => {
  const local = createLocalSigner(generateSecretKey())
  const localKey = await local.getPublicKey()
  if (!localKey.success) throw new Error("local signer has no key")
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      signEvent: async (event) => {
        const signed = await local.signEvent(event)
        return signed.success ? signed.value : null
      },
    })),
    getUserPubkey: () => localKey.value,
  })

  const result = await signer.signEvent(buildTextNote("hi", 1))

  assertEquals(result.success && result.value.pubkey, localKey.value)
})
