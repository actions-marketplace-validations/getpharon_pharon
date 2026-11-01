// Signature checks for everything the server sends that the CLI acts on: incidents, the feed key list, the service map.
import { createPublicKey, verify } from "node:crypto";
import { canonical } from "./match.mjs";
import { FEED_KEYS, ROOT_KEYS } from "./keys.mjs";

/** Verify an Ed25519 signature over canonical JSON (the doc minus `signature`). Returns the key id or throws. */
export function verifyDoc(doc, keys, what = "document") {
  const sig = doc?.signature;
  if (!sig || sig.alg !== "ed25519" || typeof sig.value !== "string") throw new Error(`${what} is not signed`);
  const pub = keys[sig.key_id];
  if (!pub) throw new Error(`${what} signed with unknown key "${sig.key_id}"`);
  const { signature: _s, ...body } = doc;
  const key = createPublicKey({ key: Buffer.from(pub, "base64"), format: "der", type: "spki" });
  if (!verify(null, Buffer.from(canonical(body)), key, Buffer.from(sig.value, "base64"))) throw new Error(`${what} signature is INVALID; refusing to use it`);
  return sig.key_id;
}

/**
 * Trusted feed keys: the ones shipped with this CLI, plus a key list signed by a shipped root key.
 * The list can add keys (rotation) and revoke or expire keys, including shipped ones.
 */
export function feedKeys(list, { roots = ROOT_KEYS, shipped = FEED_KEYS, now = new Date().toISOString() } = {}) {
  const keys = { ...shipped };
  if (!list) return keys;
  verifyDoc(list, roots, "feed key list");
  for (const k of list.keys ?? []) {
    if (k.revoked || (k.not_after && k.not_after < now)) delete keys[k.key_id];
    else if (k.alg === "ed25519" && typeof k.public_key === "string") keys[k.key_id] = k.public_key;
  }
  return keys;
}
