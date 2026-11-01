// Trusted signing keys (Ed25519, SPKI DER base64), keyed by key_id. These ship inside the CLI.
// FEED_KEYS sign incidents and the service map. ROOT_KEYS only sign the feed key list served at /v1/feed/keys,
// which can add (rotate) or revoke feed keys without a CLI release. Root private keys stay offline.
// A developer machine can trust its own dev server's keys in a git-ignored keys.local.mjs; it is never shipped.
const local = await import("./keys.local.mjs").catch((e) => (e.code === "ERR_MODULE_NOT_FOUND" ? {} : Promise.reject(e)));

export const FEED_KEYS = {
  "feed-prod-2026-10": "MCowBQYDK2VwAyEAojIBbngVaPAQX40I03m2RjZzfanl2F6TJlh5kE+gOq8=",
  ...local.FEED_KEYS,
};

export const ROOT_KEYS = {
  "root-prod-2026-10": "MCowBQYDK2VwAyEAw5smbe+syxuKWzHVxP4yteWWXoeR4LSpGu3NQReskzw=",
  ...local.ROOT_KEYS,
};
