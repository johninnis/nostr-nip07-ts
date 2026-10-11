import { assertEquals } from "@std/assert"
import { failure } from "@innis/nostr-core"
import type { NostrEvent, Result, Signer, SignerFailure, UnsignedEvent } from "@innis/nostr-core"
import { buildEventFixture } from "@innis/nostr-core/testing"
import type { EventOverrides } from "@innis/nostr-core/testing"
import { createNip07Signer } from "../src/nip07-signer-adapter.ts"
import type { NostrExtension } from "../src/nip07-signer-adapter.ts"
import { acceptAnySignature, ALICE, BOB, buildExtension, provide } from "./support/fake-extension.ts"

const EVENT_TAG = ["e", "e".repeat(64)] as const
const PUBKEY_TAG = ["p", "f".repeat(64)] as const

const TEMPLATE: UnsignedEvent = { kind: 1, content: "hi", tags: [EVENT_TAG, PUBKEY_TAG], created_at: 1 }

const DIFFERS_FROM_TEMPLATE: Result<NostrEvent, SignerFailure> = failure({
  type: "sign-failed",
  message: "Signer returned an event that differs from the template it was asked to sign",
})

const signingWith = (changes: EventOverrides): NostrExtension =>
  buildExtension({ signEvent: (event) => Promise.resolve(buildEventFixture({ ...event, pubkey: ALICE, ...changes })) })

const signerFor = (extension: NostrExtension): Signer =>
  createNip07Signer({
    getExtension: provide(extension),
    getUserPubkey: () => ALICE,
    verifyEventSignature: acceptAnySignature,
  })

Deno.test("signEvent - returns sign-failed when the extension changes the kind", async () => {
  const result = await signerFor(signingWith({ kind: 7 })).signEvent(TEMPLATE)

  assertEquals(result, DIFFERS_FROM_TEMPLATE)
})

Deno.test("signEvent - returns sign-failed when the extension changes the content", async () => {
  const result = await signerFor(signingWith({ content: "altered" })).signEvent(TEMPLATE)

  assertEquals(result, DIFFERS_FROM_TEMPLATE)
})

Deno.test("signEvent - returns sign-failed when the extension changes created_at", async () => {
  const result = await signerFor(signingWith({ created_at: 2 })).signEvent(TEMPLATE)

  assertEquals(result, DIFFERS_FROM_TEMPLATE)
})

Deno.test("signEvent - returns sign-failed when the extension changes a tag's value", async () => {
  const result = await signerFor(signingWith({ tags: [["e", "d".repeat(64)], PUBKEY_TAG] })).signEvent(TEMPLATE)

  assertEquals(result, DIFFERS_FROM_TEMPLATE)
})

Deno.test("signEvent - returns sign-failed when the extension reorders the tags", async () => {
  const result = await signerFor(signingWith({ tags: [PUBKEY_TAG, EVENT_TAG] })).signEvent(TEMPLATE)

  assertEquals(result, DIFFERS_FROM_TEMPLATE)
})

Deno.test("signEvent - returns sign-failed when the extension adds a tag", async () => {
  const result = await signerFor(signingWith({ tags: [EVENT_TAG, PUBKEY_TAG, ["client", "extension"]] }))
    .signEvent(TEMPLATE)

  assertEquals(result, DIFFERS_FROM_TEMPLATE)
})

Deno.test("signEvent - returns sign-failed when the extension drops a tag", async () => {
  const result = await signerFor(signingWith({ tags: [EVENT_TAG] })).signEvent(TEMPLATE)

  assertEquals(result, DIFFERS_FROM_TEMPLATE)
})

Deno.test("signEvent - returns sign-failed when the extension appends an element to a tag", async () => {
  const result = await signerFor(signingWith({ tags: [[...EVENT_TAG, "wss://relay.example.com"], PUBKEY_TAG] }))
    .signEvent(TEMPLATE)

  assertEquals(result, DIFFERS_FROM_TEMPLATE)
})

Deno.test("signEvent - returns the event when the extension adds only id, pubkey and sig to the template", async () => {
  const result = await signerFor(signingWith({})).signEvent(TEMPLATE)

  assertEquals(result.success, true)
})

Deno.test("signEvent - compares with the template as sent, with the d tag an addressable kind gains", async () => {
  const result = await signerFor(signingWith({})).signEvent({ kind: 30023, content: "", tags: [], created_at: 1 })

  assertEquals(result.success, true)
})

Deno.test("signEvent - returns pubkey-mismatch for another key's event that also differs from the template", async () => {
  const result = await signerFor(signingWith({ pubkey: BOB, content: "altered" })).signEvent(TEMPLATE)

  assertEquals(!result.success && result.error.type, "pubkey-mismatch")
})

Deno.test("signEvent - refuses an event that differs from the template before verifying its signature", async () => {
  const signer = createNip07Signer({
    getExtension: provide(signingWith({ content: "altered" })),
    getUserPubkey: () => ALICE,
    verifyEventSignature: () => false,
  })

  assertEquals(await signer.signEvent(TEMPLATE), DIFFERS_FROM_TEMPLATE)
})

Deno.test("signEvent - without getUserPubkey, an event that differs from the template pins no identity", async () => {
  let changes: EventOverrides = { pubkey: BOB, content: "altered" }
  const signer = createNip07Signer({
    getExtension: provide(buildExtension({
      signEvent: (event) => Promise.resolve(buildEventFixture({ ...event, ...changes })),
    })),
    getUserPubkey: () => null,
    verifyEventSignature: acceptAnySignature,
  })
  await signer.signEvent(TEMPLATE)
  changes = { pubkey: ALICE }

  const result = await signer.signEvent(TEMPLATE)

  assertEquals(result.success, true)
})
