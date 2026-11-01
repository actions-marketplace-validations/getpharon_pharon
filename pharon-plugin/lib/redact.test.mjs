import { test } from "node:test";
import assert from "node:assert/strict";
import { redact, validPattern } from "./redact.mjs";

const cs = [
  { type: "package", ecosystem: "npm", name: "@acme/billing-core", version: "1.0.0", purl: "pkg:npm/%40acme/billing-core@1.0.0", locations: ["package-lock.json"] },
  { type: "package", ecosystem: "npm", name: "react", version: "18.2.0", locations: ["apps/secret-launch/package.json"] },
  { type: "service", vendor: "stripe", evidence: ["env_name:STRIPE_SECRET_KEY"] },
  { type: "container_image", name: "ghcr.io/acme/internal-api", tag: "1.2", locations: ["Dockerfile:1"] },
];

test("drop and hash rules", () => {
  const out = redact(cs, [{ pattern: "@acme/*", action: "hash" }, { pattern: "apps/secret-*", action: "hash" }, { pattern: "ghcr.io/acme/*", action: "drop" }], "salt1");
  assert.equal(out.length, 3);
  assert.match(out[0].name, /^redacted-[0-9a-f]{12}$/);
  assert.equal(out[0].purl, undefined);
  assert.notEqual(redact(cs, [{ pattern: "@acme/*", action: "hash" }], "salt2")[0].name, out[0].name, "salted per org");
  assert.deepEqual([out[1].name, out[1].locations], ["react", ["redacted"]], "path-only hit hides the path, keeps the name");
  assert.ok(!JSON.stringify(out).includes("internal-api"));
  assert.ok(!JSON.stringify(out).includes("billing"));
});

test("evidence naming a redacted package is scrubbed too", () => {
  const svc = [{ type: "service", vendor: "aws", evidence: ["package:boto3", "env_name:AWS_REGION"] }];
  assert.deepEqual(redact(svc, [{ pattern: "boto3", action: "drop" }])[0].evidence, ["env_name:AWS_REGION"]);
  assert.deepEqual(redact(svc, [{ pattern: "boto3", action: "hash" }])[0].evidence, ["package:redacted", "env_name:AWS_REGION"]);
  assert.equal(redact(svc, [{ pattern: "nothing", action: "drop" }])[0], svc[0], "untouched components are the same object");
});

test("no rules or invalid patterns leave components alone", () => {
  assert.equal(redact(cs, []), cs);
  assert.equal(redact(cs, [{ pattern: "a b c", action: "drop" }]), cs);
  assert.ok(validPattern("@acme/*") && !validPattern("x$(rm)"));
});
