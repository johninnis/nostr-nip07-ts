import { assertEquals } from "@std/assert"
import { buildEventFixture } from "@innis/nostr-core/testing"
import { createNip07Signer } from "../src/nip07-signer-adapter.ts"
import { acceptAnySignature, ALICE, BOB, buildExtension, provide } from "./support/fake-extension.ts"

Deno.test("signEvent - checks the current getUserPubkey after getPublicKey has cached an earlier one", async () => {
  let sessionPubkey = ALICE
  const signer = createNip07Signer({
    getExtension: provide(buildExtension()),
    getUserPubkey: () => sessionPubkey,
    verifyEventSignature: acceptAnySignature,
  })
  await signer.getPublicKey()
  sessionPubkey = BOB

  const result = await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 })

  assertEquals(!result.success && result.error.type, "pubkey-mismatch")
})

Deno.test("signEvent - without getUserPubkey, refuses a key other than the one getPublicKey resolved", async () => {
  let current = ALICE
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      getPublicKey: () => Promise.resolve(current),
      signEvent: (event) => Promise.resolve(buildEventFixture({ ...event, pubkey: current })),
    })),
    getUserPubkey: () => null,
    verifyEventSignature: acceptAnySignature,
  })
  await signer.getPublicKey()
  current = BOB

  const result = await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 })

  assertEquals(!result.success && result.error.type, "pubkey-mismatch")
})

Deno.test("signEvent - without getUserPubkey, pins the first signing key and refuses a later switch", async () => {
  let current = ALICE
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      signEvent: (event) => Promise.resolve(buildEventFixture({ ...event, pubkey: current })),
    })),
    getUserPubkey: () => null,
    verifyEventSignature: acceptAnySignature,
  })
  const first = await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 1 })
  current = BOB

  const second = await signer.signEvent({ kind: 1, content: "hi", tags: [], created_at: 2 })

  assertEquals([first.success, !second.success && second.error.type], [true, "pubkey-mismatch"])
})
