import { buildEventFixture, publicKeyFixture } from "@innis/nostr-core/testing"
import type { NostrExtension } from "../../src/nip07-signer-adapter.ts"

export const ALICE = publicKeyFixture("a".repeat(64))
export const BOB = publicKeyFixture("b".repeat(64))
export const CAROL = publicKeyFixture("c".repeat(64))

export const acceptAnySignature = (): boolean => true

export const noExtension = (): NostrExtension | null => null
export const provide = (ext: NostrExtension): () => NostrExtension | null => () => ext

export const buildExtension = (overrides: Partial<NostrExtension> = {}): NostrExtension => ({
  getPublicKey: () => Promise.resolve(ALICE),
  signEvent: (event) => Promise.resolve(buildEventFixture({ ...event, pubkey: ALICE })),
  ...overrides,
})
