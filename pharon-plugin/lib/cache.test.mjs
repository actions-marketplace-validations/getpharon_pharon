import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

// check.mjs reads the home directory at load time, so point HOME at a fake one first.
const home = mkdtempSync(path.join(tmpdir(), "pharon-home-"));
process.env.HOME = home;
process.env.XDG_CACHE_HOME = path.join(home, ".cache");
delete process.env.npm_config_cache;
const { runCheck } = await import("./check.mjs");

const touch = (p, body = "") => (mkdirSync(path.dirname(p), { recursive: true }), writeFileSync(p, body));

test("finds affected artifacts in npm, yarn berry, uv and pip caches", () => {
  const key = "make-fetch-happen:request-cache:https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.1.tgz";
  const h = createHash("sha256").update(key).digest("hex");
  touch(path.join(home, ".npm/_cacache/index-v5", h.slice(0, 2), h.slice(2, 4), h.slice(4)));
  touch(path.join(home, ".yarn/berry/cache/@scope-lib-npm-2.0.0-abcdef1234-8.zip"));
  touch(path.join(home, ".yarn/berry/cache/@scope-lib-npm-2.1.0-abcdef1234-8.zip"));
  mkdirSync(path.join(home, ".cache/uv/archive-v0/x1/Lite_LLM-1.107.0.dist-info"), { recursive: true });
  const repo = mkdtempSync(path.join(tmpdir(), "pharon-repo-"));
  const r = runCheck(repo, {
    affects: [
      { kind: "package", ecosystem: "npm", name: "evil-pkg", versions: ["1.0.1"] },
      { kind: "package", ecosystem: "npm", name: "@scope/lib", ranges: [{ introduced: "2.0.0", fixed: "2.1.0" }] },
      { kind: "package", ecosystem: "pypi", name: "lite-llm", versions: ["1.107.0"] },
    ],
  }, "k");
  const ev = Object.fromEntries(r.locations.filter((l) => l.label.startsWith("cache:")).map((l) => [l.label, l.evidence.join(" | ")]));
  assert.match(ev["cache: npm"], /evil-pkg 1\.0\.1/);
  assert.match(ev["cache: yarn"], /@scope\/lib 2\.0\.0/);
  assert.doesNotMatch(ev["cache: yarn"], /2\.1\.0/, "fixed version is not reported");
  assert.match(ev["cache: uv"], /lite-llm 1\.107\.0/);
  assert.equal(r.verdict, "likely");
});
