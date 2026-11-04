import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { canonical } from "./match.mjs";
import { runCheck, verifyIncident } from "./check.mjs";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const KEYS = { "test-key": publicKey.export({ format: "der", type: "spki" }).toString("base64") };
const signed = (doc) => ({ ...doc, signature: { key_id: "test-key", alg: "ed25519", value: sign(null, Buffer.from(canonical(doc)), privateKey).toString("base64") } });

const INCIDENT = {
  schema_version: "1.0",
  id: "litellm-2026-10",
  type: "package_compromise",
  severity: "critical",
  title: "Malicious LiteLLM 1.107.0",
  affects: [{ kind: "package", ecosystem: "pypi", name: "litellm", versions: ["1.107.0"] }],
  exposure_window: { start: "2026-10-21T11:00:00Z", end: "2026-10-21T17:00:00Z" },
  indicators: { files: [{ pattern: "site-packages/*litellm*.pth", description: "Malicious startup hook" }] },
  targets: ["ai_api_keys", "environment_variables"],
  remediation: ["Rotate keys"],
};

test("signature: valid passes, tampering and unknown keys are rejected", () => {
  const doc = signed(INCIDENT);
  assert.equal(verifyIncident(doc, KEYS), "test-key");
  assert.throws(() => verifyIncident({ ...doc, affects: [] }, KEYS), /INVALID/);
  assert.throws(() => verifyIncident({ ...doc, signature: { ...doc.signature, key_id: "other" } }, KEYS), /unknown key/);
  assert.throws(() => verifyIncident(INCIDENT, KEYS), /not signed/);
});

test("runCheck: lockfile pin is safe, installed malicious version and indicator are confirmed", () => {
  const root = mkdtempSync(path.join(tmpdir(), "pharon-check-"));
  const sp = path.join(root, ".venv/lib/python3.12/site-packages");
  mkdirSync(path.join(sp, "litellm-1.107.0.dist-info"), { recursive: true });
  writeFileSync(path.join(sp, "litellm_init.pth"), "import os  # never opened by the checker");
  mkdirSync(path.join(root, "api"));
  writeFileSync(path.join(root, "api/requirements.txt"), "litellm==1.106.2\n");
  mkdirSync(path.join(root, "worker"));
  writeFileSync(path.join(root, "worker/requirements.txt"), "litellm>=1.100\n");
  writeFileSync(path.join(root, ".env.example"), "OPENAI_API_KEY=\nPORT=3000\n");

  const r = runCheck(root, INCIDENT, "test-key");
  const byLabel = Object.fromEntries(r.locations.map((l) => [l.label, l.verdict]));
  assert.equal(r.verdict, "confirmed");
  assert.equal(byLabel["repo: api/requirements.txt"], "not_affected");
  assert.equal(byLabel["repo: worker/requirements.txt"], "likely");
  assert.equal(Object.entries(byLabel).find(([k]) => k.startsWith("env:") && k.endsWith(".venv"))?.[1], "confirmed");
  assert.ok(r.locations.some((l) => l.label.startsWith("indicator:") && l.label.endsWith("litellm_init.pth")));
  assert.ok(r.rotate.some((x) => x.name === "OPENAI_API_KEY" && x.target === "ai_api_keys"));
  assert.ok(r.rotate.some((x) => x.name === "PORT" && x.target === "environment_variables"), "declared env names are listed for the catch-all target");
  assert.equal(r.rotate_now, true);
});

test("docker: local images are matched by repository and tag (fake docker on PATH)", () => {
  const bin = mkdtempSync(path.join(tmpdir(), "pharon-bin-"));
  const lines = [
    { Repository: "litellm/litellm", Tag: "1.107.0", Digest: "<none>", ID: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CreatedAt: "2026-10-21 12:00:00 +0000 UTC" },
    { Repository: "docker.io/litellm/litellm", Tag: "1.106.2", Digest: "<none>", ID: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CreatedAt: "2026-10-01 12:00:00 +0000 UTC" },
    { Repository: "postgres", Tag: "16", Digest: "<none>", ID: "sha256:cccccccccccccccccccccccccccccccccccccccc", CreatedAt: "2026-09-01 12:00:00 +0000 UTC" },
  ];
  writeFileSync(path.join(bin, "docker"), `#!/bin/sh\ncat <<'JSON'\n${lines.map((l) => JSON.stringify(l)).join("\n")}\nJSON\n`, { mode: 0o755 });
  const PATH = process.env.PATH;
  process.env.PATH = `${bin}:${PATH}`;
  try {
    const root = mkdtempSync(path.join(tmpdir(), "pharon-check-"));
    const r = runCheck(root, { affects: [{ kind: "container_image", name: "litellm/litellm", tags: ["1.107.0"] }] }, "k");
    const v = Object.fromEntries(r.locations.map((l) => [l.label, l.verdict]));
    assert.equal(v["docker: litellm/litellm:1.107.0"], "confirmed");
    assert.equal(v["docker: docker.io/litellm/litellm:1.106.2"], "not_affected");
    assert.ok(!Object.keys(v).some((k) => k.includes("postgres")));
    assert.equal(r.verdict, "confirmed");
  } finally {
    process.env.PATH = PATH;
  }
});

test("runCheck: a service the team confirmed in setup counts, though no file scan finds it", () => {
  const root = mkdtempSync(path.join(tmpdir(), "pharon-check-"));
  const doc = { affects: [{ kind: "service", vendor: "northflank" }], targets: ["environment_variables"] };
  assert.equal(runCheck(root, doc, "k").verdict, "not_affected");
  const r = runCheck(root, doc, "k", [{ vendor: "northflank", evidence: ["file:northflank.json"] }]);
  assert.equal(r.verdict, "likely");
  assert.equal(r.rotate_now, true);
});
