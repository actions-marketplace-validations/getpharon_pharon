// Regressions from the security review.
import { test } from "node:test";
import assert from "node:assert/strict";
import { detect } from "./detect.mjs";
import { redact } from "./redact.mjs";
import { globMatch } from "./match.mjs";

test("redaction globs run in linear time (no ReDoS)", () => {
  const evil = "*a".repeat(25) + "*b";
  const t = Date.now();
  redact([{ type: "package", ecosystem: "npm", name: "a".repeat(40), locations: [] }], [{ pattern: evil, action: "drop" }]);
  assert.ok(Date.now() - t < 200, `took ${Date.now() - t} ms`);
  assert.ok(globMatch("@acme/*", "@ACME/billing") && globMatch("*core*", "billing-core-x") && !globMatch("a*b", "ab-c"));
  assert.ok(globMatch("a*a", "aba") && !globMatch("a*a", "a"));
});

test("credentials in URL-style specs are never uploaded", () => {
  const { components } = detect(new Map([
    ["package.json", JSON.stringify({ dependencies: { priv: "git+https://ghp_SECRET:x-oauth-basic@github.com/acme/priv.git", ok: "^1.2.0" } })],
    ["legacy/package-lock.json", JSON.stringify({ lockfileVersion: 1, dependencies: { gitdep: { version: "git+ssh://git@github.com/acme/gitdep.git#0123abc" } } })],
  ]));
  const all = JSON.stringify(components);
  assert.ok(!all.includes("ghp_SECRET") && !all.includes("github.com/acme"), all);
  const priv = components.find((c) => c.name === "priv");
  assert.equal(priv.version_spec, "git+https:(redacted)");
  assert.equal(components.find((c) => c.name === "ok").version_spec, "^1.2.0");
  assert.equal(components.find((c) => c.name === "gitdep").version, null);
});

test("CRLF files parse like LF files", () => {
  const crlf = (s) => s.replace(/\n/g, "\r\n");
  const { components } = detect(new Map([
    ["yarn.lock", crlf(`lodash@^4.17.21:\n  version "4.17.21"\n`)],
    ["package.json", crlf(JSON.stringify({ dependencies: { lodash: "^4.17.21" } }, null, 2))],
    ["py/pyproject.toml", crlf(`[project]\ndependencies = [\n  "litellm>=1.100",\n]\n`)],
  ]));
  assert.ok(components.some((c) => c.name === "lodash" && c.version === "4.17.21"));
  assert.ok(components.some((c) => c.name === "litellm" && c.version_spec === ">=1.100"));
});

test("malformed files never break a sync; terraform comments don't shift blocks; cdk.json doesn't hide the AWS gap", async () => {
  const { detectGaps } = await import("./detect.mjs");
  const { components } = detect(new Map([
    ["composer.lock", JSON.stringify({ packages: [{ name: 42, version: "1.0" }, { name: "ok/pkg", version: "2.0.0" }] })],
    ["main.tf", '# legacy } brace in a comment\nresource "aws_db_instance" "db" {\n  engine = "postgres" // }\n  engine_version = "15.4"\n  description = "a } in a string"\n}\n'],
  ]));
  assert.ok(components.some((c) => c.name === "ok/pkg"));
  assert.ok(components.some((c) => c.type === "cloud_resource" && c.engine === "postgres" && c.version === "15.4"));
  assert.deepEqual(detectGaps([{ type: "service", vendor: "aws" }], ["cdk.json"]).map((g) => g.id), ["aws-resources"]);
});
