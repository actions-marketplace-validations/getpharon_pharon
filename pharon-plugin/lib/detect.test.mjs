import { test } from "node:test";
import assert from "node:assert/strict";
import { detect, isStackFile, parseImageRef } from "./detect.mjs";
import { normalizeRemote } from "./git.mjs";

const find = (cs, pred) => cs.filter(pred);
const pkg = (cs, eco, name) => cs.filter((c) => c.type === "package" && c.ecosystem === eco && c.name === name);

test("normalizeRemote strips credentials and .git", () => {
  assert.equal(normalizeRemote("git@github.com:Acme/API.git"), "github.com/acme/api");
  assert.equal(normalizeRemote("https://user:s3cret@github.com/acme/api.git"), "github.com/acme/api");
  assert.equal(normalizeRemote("ssh://git@gitlab.com:2222/group/sub/repo.git"), "gitlab.com/group/sub/repo");
  assert.equal(normalizeRemote(null), null);
});

test("isStackFile", () => {
  assert.ok(isStackFile("services/api/uv.lock"));
  assert.ok(isStackFile("Dockerfile.prod"));
  assert.ok(isStackFile(".github/workflows/ci.yml"));
  assert.ok(!isStackFile("node_modules/foo/package.json"));
  assert.ok(!isStackFile(".env"));
  assert.ok(!isStackFile("src/index.ts"));
});

test("parseImageRef", () => {
  assert.deepEqual(parseImageRef("python:3.12-slim"), { name: "python", tag: "3.12-slim", digest: null });
  assert.deepEqual(parseImageRef("localhost:5000/app"), { name: "localhost:5000/app", tag: "latest", digest: null });
  assert.deepEqual(parseImageRef("ghcr.io/a/b@sha256:abc"), { name: "ghcr.io/a/b", tag: null, digest: "sha256:abc" });
});

test("npm: lockfile wins over package.json, direct flag from manifest", () => {
  const files = new Map([
    ["package.json", JSON.stringify({ dependencies: { stripe: "^14.0.0" }, engines: { node: ">=20" } })],
    ["package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { stripe: "^14.0.0" } }, "node_modules/stripe": { version: "14.2.0" }, "node_modules/qs": { version: "6.11.0" }, "node_modules/@scope/x": { version: "1.0.0" } } })],
    ["apps/web/package.json", JSON.stringify({ dependencies: { openai: "4.20.0", react: "^18" } })],
  ]);
  const { components: cs } = detect(files);
  assert.deepEqual(pkg(cs, "npm", "stripe").map((c) => [c.version, c.direct]), [["14.2.0", true]]);
  assert.equal(pkg(cs, "npm", "qs")[0].direct, false);
  assert.equal(pkg(cs, "npm", "@scope/x")[0].purl, "pkg:npm/%40scope/x@1.0.0");
  // apps/web is covered by the root lockfile, so its manifest adds no loose entries
  assert.equal(pkg(cs, "npm", "react").length, 0);
  assert.ok(find(cs, (c) => c.type === "service" && c.vendor === "stripe").length);
  assert.ok(find(cs, (c) => c.type === "runtime" && c.name === "node" && c.version === ">=20").length);
});

test("npm without lockfile records loose ranges", () => {
  const { components: cs } = detect(new Map([["package.json", JSON.stringify({ dependencies: { a: "^1.0.0", b: "2.3.4" } })]]));
  assert.equal(pkg(cs, "npm", "a")[0].loose_range, true);
  assert.equal(pkg(cs, "npm", "b")[0].version, "2.3.4");
});

test("pnpm v9 and v6, yarn v1 and berry, bun", () => {
  const pnpm9 = `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      react:\n        specifier: ^18\n        version: 18.2.0\npackages:\n  react@18.2.0:\n    resolution: {integrity: x}\n  '@babel/core@7.24.0':\n    resolution: {integrity: y}\nsnapshots:\n  react-dom@18.2.0(react@18.2.0):\n    dependencies: {}\n`;
  const pnpm6 = `lockfileVersion: '6.0'\ndependencies:\n  lodash:\n    specifier: ^4\n    version: 4.17.21\npackages:\n  /lodash@4.17.21:\n    resolution: {integrity: x}\n  /string_decoder@1.3.0:\n    dev: false\n`;
  const yarn1 = `# yarn lockfile v1\n\n"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.1.0":\n  version "7.23.5"\n  resolved "https://x"\n\nlodash@^4.17.21:\n  version "4.17.21"\n`;
  const berry = `__metadata:\n  version: 8\n\n"left-pad@npm:^1.3.0":\n  version: 1.3.0\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n`;
  const bun = `{\n  "lockfileVersion": 1,\n  "workspaces": { "": { "dependencies": { "zod": "^3" } } },\n  "packages": {\n    "zod": ["zod@3.22.4", "", {}, "sha512-x"],\n  },\n}\n`;
  const a = detect(new Map([["a/pnpm-lock.yaml", pnpm9], ["b/pnpm-lock.yaml", pnpm6], ["c/yarn.lock", yarn1], ["d/yarn.lock", berry], ["e/bun.lock", bun]])).components;
  assert.deepEqual(pkg(a, "npm", "react").map((c) => [c.version, c.direct]), [["18.2.0", true]]);
  assert.equal(pkg(a, "npm", "@babel/core")[0].version, "7.24.0");
  assert.equal(pkg(a, "npm", "react-dom").length, 0, "snapshots section ignored");
  assert.equal(pkg(a, "npm", "lodash").length, 1, "same version in two lockfiles merges");
  assert.deepEqual(pkg(a, "npm", "lodash")[0].locations.sort(), ["b/pnpm-lock.yaml", "c/yarn.lock"]);
  assert.equal(pkg(a, "npm", "string_decoder")[0].version, "1.3.0");
  assert.equal(pkg(a, "npm", "@babel/code-frame")[0].version, "7.23.5");
  assert.equal(pkg(a, "npm", "left-pad")[0].version, "1.3.0");
  assert.equal(pkg(a, "npm", "app").length, 0, "workspace packages skipped");
  assert.deepEqual(pkg(a, "npm", "zod").map((c) => [c.version, c.direct]), [["3.22.4", true]]);
});

test("python: uv.lock, requirements pins and loose ranges, pyproject", () => {
  const uv = `version = 1\n\n[[package]]\nname = "myapp"\nversion = "0.1.0"\nsource = { editable = "." }\ndependencies = [\n    { name = "litellm" },\n]\n\n[[package]]\nname = "litellm"\nversion = "1.106.2"\nsource = { registry = "https://pypi.org/simple" }\n\n[package.optional-dependencies]\nproxy = [\n    { name = "fastapi" },\n]\n\n[[package]]\nname = "httpx"\nversion = "0.27.0"\n`;
  const pyproject = `[project]\nname = "myapp"\nrequires-python = ">=3.11"\ndependencies = [\n  "litellm>=1.100",\n  "requests[socks] (>=2.28)",\n]\n`;
  const files = new Map([
    ["services/api/uv.lock", uv],
    ["services/api/pyproject.toml", pyproject],
    ["worker/requirements.txt", "# deps\nlitellm>=1.100\nboto3==1.34.0 \\\n    --hash=sha256:abc\n-r base.txt\ngit+https://github.com/x/y.git\n"],
  ]);
  const { components: cs } = detect(files);
  const lit = pkg(cs, "pypi", "litellm");
  assert.deepEqual(lit.map((c) => [c.version, c.version_spec, !!c.loose_range]).sort(), [["1.106.2", "==1.106.2", false], [null, ">=1.100", true]].sort());
  assert.equal(lit.find((c) => c.version).direct, true, "direct because pyproject lists it");
  assert.equal(pkg(cs, "pypi", "httpx")[0].direct, false);
  assert.equal(pkg(cs, "pypi", "myapp").length, 0, "editable project itself skipped");
  assert.equal(pkg(cs, "pypi", "boto3")[0].version, "1.34.0");
  assert.equal(pkg(cs, "pypi", "requests").length, 0, "pyproject covered by uv.lock adds no loose entries");
  assert.ok(find(cs, (c) => c.type === "runtime" && c.name === "python" && c.version === ">=3.11").length);
  assert.ok(find(cs, (c) => c.type === "service" && c.vendor === "aws").length);
});

test("docker, compose, workflows, runtimes, env names", () => {
  const files = new Map([
    ["Dockerfile", "ARG PY=3.12\nFROM python:${PY}-slim AS build\nRUN pip install x\nFROM build\nFROM --platform=linux/amd64 litellm/litellm:1.107.0\nFROM scratch\n"],
    ["docker-compose.yml", "services:\n  db:\n    image: postgres:15.4\n  cache:\n    image: \"redis:${REDIS_TAG:-7.0}\"\n"],
    [".github/workflows/ci.yml", "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: github/codeql-action/init@0123456789abcdef0123456789abcdef01234567\n      - uses: ./.github/actions/local\n"],
    [".nvmrc", "v20.11.1\n"],
    [".tool-versions", "nodejs 20.11.1\npython 3.12.1\n"],
    [".env.example", "STRIPE_SECRET_KEY=sk_test_xxx\nexport SENTRY_DSN=\nFOO=bar\n"],
    ["fly.toml", "app = 'x'\n"],
  ]);
  const { components: cs } = detect(files);
  const images = find(cs, (c) => c.type === "container_image").map((c) => `${c.name}:${c.tag}`).sort();
  assert.deepEqual(images, ["litellm/litellm:1.107.0", "postgres:15.4", "python:3.12-slim", "redis:7.0"]);
  assert.ok(find(cs, (c) => c.type === "runtime" && c.name === "python" && c.version === "3.12").length, "runtime from base image");
  const actions = find(cs, (c) => c.type === "ci_action");
  assert.deepEqual(actions.map((a) => [a.name, a.pinned_to_sha]).sort(), [["actions/checkout", false], ["github/codeql-action", true]]);
  const node = find(cs, (c) => c.type === "runtime" && c.name === "node");
  assert.equal(node.length, 1);
  assert.deepEqual(node[0].locations.sort(), [".nvmrc", ".tool-versions"]);
  const vendors = find(cs, (c) => c.type === "service").map((c) => c.vendor).sort();
  assert.deepEqual(vendors, ["fly", "sentry", "stripe"]);
  assert.ok(!JSON.stringify(cs).includes("sk_test"), "env values never read");
});

test("gap rules", async () => {
  const { detectGaps } = await import("./detect.mjs");
  const svc = (vendor) => ({ type: "service", vendor });
  const ids = (cs, files = [], env = []) => detectGaps(cs, files, new Set(env)).map((g) => g.id).sort();
  assert.deepEqual(ids([svc("aws"), svc("postgresql"), svc("redis")]), ["aws-resources", "postgresql-version", "redis-version"]);
  assert.deepEqual(ids([svc("aws")], ["infra/main.tf"]), [], "IaC describes AWS");
  assert.deepEqual(ids([svc("redis"), { type: "container_image", name: "redis", tag: "7.2" }]), [], "compose image gives the version");
  assert.deepEqual(ids([svc("postgresql"), { type: "cloud_resource", provider: "aws", service: "rds", engine: "postgres", version: "15.4" }]), []);
  assert.deepEqual(ids([], [], ["DATABASE_URL"]), ["database-provider"]);
  assert.deepEqual(ids([svc("google-cloud")]), ["google-cloud-resources"]);
});
