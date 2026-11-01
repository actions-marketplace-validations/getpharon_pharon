import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { canonical } from "./match.mjs";
import { feedKeys, verifyDoc } from "./feedsig.mjs";

const pair = () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, pub: publicKey.export({ format: "der", type: "spki" }).toString("base64") };
};
const signWith = (doc, keyId, k) => ({ ...doc, signature: { key_id: keyId, alg: "ed25519", value: sign(null, Buffer.from(canonical(doc)), k.privateKey).toString("base64") } });

const root = pair();
const oldFeed = pair();
const newFeed = pair();
const opts = { roots: { r1: root.pub }, shipped: { "feed-old": oldFeed.pub } };

test("key list signed by a root key rotates and revokes feed keys", () => {
  const list = signWith({ issued_at: "2026-10-25T00:00:00Z", keys: [{ key_id: "feed-new", alg: "ed25519", public_key: newFeed.pub }, { key_id: "feed-old", revoked: true }] }, "r1", root);
  const keys = feedKeys(list, opts);
  assert.deepEqual(Object.keys(keys), ["feed-new"]);
  assert.equal(verifyDoc(signWith({ id: "x" }, "feed-new", newFeed), keys), "feed-new");
  assert.throws(() => verifyDoc(signWith({ id: "x" }, "feed-old", oldFeed), keys), /unknown key/);
});

test("expired keys are dropped; lists not signed by a root key are rejected", () => {
  const expiring = signWith({ keys: [{ key_id: "feed-new", alg: "ed25519", public_key: newFeed.pub, not_after: "2026-01-01T00:00:00Z" }] }, "r1", root);
  assert.ok(!("feed-new" in feedKeys(expiring, { ...opts, now: "2026-10-25T00:00:00Z" })));
  const forged = signWith({ keys: [{ key_id: "evil", alg: "ed25519", public_key: newFeed.pub }] }, "r1", newFeed);
  assert.throws(() => feedKeys(forged, opts), /INVALID/);
  assert.deepEqual(Object.keys(feedKeys(null, opts)), ["feed-old"]);
});
