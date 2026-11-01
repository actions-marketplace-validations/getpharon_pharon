// Deterministic repo detectors (spec §5.3). Each parser takes file *content* so the same code can
// read the working tree or an old commit (`pharon check` looks at lockfile history).
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { git } from "./git.mjs";
import { normImage, normName } from "./match.mjs";
import { safeSpec } from "./redact.mjs";
import { serviceForEnv, serviceForFile, serviceForPackage } from "./services.mjs";

const STACK = [
  /(^|\/)package\.json$/,
  /(^|\/)(package-lock|npm-shrinkwrap)\.json$/,
  /(^|\/)pnpm-lock\.yaml$/,
  /(^|\/)yarn\.lock$/,
  /(^|\/)bun\.lockb?$/,
  /(^|\/)requirements[^/]*\.txt$/,
  /(^|\/)pyproject\.toml$/,
  /(^|\/)(poetry|uv)\.lock$/,
  /(^|\/)Pipfile\.lock$/,
  /(^|\/)\.(nvmrc|node-version|python-version|tool-versions)$/,
  /(^|\/)runtime\.txt$/,
  /(^|\/)\.?mise\.toml$/,
  /(^|\/)[^/]*Dockerfile[^/]*$/i,
  /\.dockerfile$/i,
  /(^|\/)(docker-)?compose[^/]*\.ya?ml$/,
  /^\.github\/workflows\/[^/]+\.ya?ml$/,
  /(^|\/)\.env\.(example|sample|template)$/,
  /(^|\/)(vercel\.json|fly\.toml|railway\.(json|toml)|netlify\.toml|render\.yaml|wrangler\.(toml|jsonc?))$/,
  /(^|\/)go\.mod$/,
  /(^|\/)Cargo\.(lock|toml)$/,
  /(^|\/)rust-toolchain(\.toml)?$/,
  /(^|\/)Gemfile\.lock$/,
  /(^|\/)composer\.(lock|json)$/,
  /(^|\/)pom\.xml$/,
  /(^|\/)(gradle\.lockfile|build\.gradle(\.kts)?)$/,
  /(^|\/)(packages\.lock\.json|[^/]+\.csproj)$/,
  // Infrastructure as code. Never *.tfvars or state files: they can hold secrets.
  /(^|\/)[^/]+\.tf$/,
  /(^|\/)\.terraform\.lock\.hcl$/,
  /(^|\/)cdk\.json$/,
  /(^|\/)serverless\.ya?ml$/,
  /(^|\/)(template|samconfig)\.(ya?ml|toml)$/,
];
const EXCLUDE = /(^|\/)(node_modules|\.venv|venv|vendor|dist|build|\.next|\.git|__pycache__|site-packages)\//;
const MAX_FILE = 50 * 1024 * 1024;

export const isStackFile = (rel) => !EXCLUDE.test(rel) && STACK.some((r) => r.test(rel));

/** Stack files relative to the repo root: git-tracked plus untracked-but-not-ignored. */
export function listStackFiles(root) {
  const out = git(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { raw: true });
  const all = out === null ? walk(root) : out.split("\0").filter(Boolean);
  return [...new Set(all)].filter(isStackFile).sort();
}

// Not a git repo: bounded directory walk.
function walk(root, rel = "", depth = 0, acc = []) {
  if (depth > 6) return acc;
  let entries = [];
  try {
    entries = readdirSync(path.join(root, rel), { withFileTypes: true });
  } catch {}
  for (const e of entries) {
    const p = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory() && !EXCLUDE.test(`${p}/`)) walk(root, p, depth + 1, acc);
    else if (e.isFile()) acc.push(p);
  }
  return acc;
}

const sha256 = (b) => createHash("sha256").update(b).digest("hex");

export function readStack(root, files) {
  const out = new Map();
  for (const f of files) {
    try {
      const buf = readFileSync(path.join(root, f));
      if (buf.length <= MAX_FILE) out.set(f, buf);
    } catch {} // deleted in the working tree but still in the index
  }
  return out;
}

/** SHA-256 over sorted (path, sha256(content)) pairs (spec §5.4). */
export function fingerprint(contents) {
  const h = createHash("sha256");
  for (const [f, buf] of [...contents].sort(([a], [b]) => (a < b ? -1 : 1))) h.update(`${f}\0${sha256(buf)}\n`);
  return `sha256:${h.digest("hex")}`;
}

// ---------- helpers ----------

const prov = (method, verified = true) => ({ source: "repo", method, verified });
const purl = (eco, name, version) => (version ? `pkg:${eco}/${name.replace(/^@/, "%40")}@${version}` : undefined);
const DEP_SECTIONS = new Set(["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]);
const firstLine = (s) => s.split("\n").map((l) => l.trim()).find((l) => l && !l.startsWith("#")) ?? null;
/** A spec that pins one exact version ("1.2.3" in npm, "==1.2.3" in PyPI), or undefined. */
// Cargo/RubyGems/Go treat a bare version as a range; Maven/NuGet/Composer pin it.
const exactVersion = (eco, spec) =>
  eco === "npm" ? spec.match(/^=?v?(\d+\.\d+\.\d+[\w.+-]*)$/)?.[1]
  : eco === "pypi" ? spec.match(/^===?([^,*]+)$/)?.[1]
  : ["maven", "nuget", "packagist"].includes(eco) ? spec.match(/^\[?=?v?(\d+(?:\.\d+)+[\w.+-]*)\]?$/)?.[1]
  : undefined;
const dirOf = (rel) => (rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "");
const RUNTIME_ALIASES = { nodejs: "node", node: "node", python: "python", golang: "go", go: "go", ruby: "ruby", java: "java", bun: "bun", deno: "deno", rust: "rust", php: "php" };

// ---------- JavaScript ----------

function parsePackageJson(text) {
  const j = JSON.parse(text);
  const deps = {};
  for (const s of DEP_SECTIONS) Object.assign(deps, j[s] ?? {});
  return { deps, node: j.engines?.node ?? null };
}

function parseNpmLock(text) {
  const j = JSON.parse(text);
  const pkgs = [];
  const direct = new Set();
  if (j.packages) {
    for (const [k, v] of Object.entries(j.packages)) {
      if (!k.includes("node_modules/")) {
        for (const s of DEP_SECTIONS) for (const n of Object.keys(v[s] ?? {})) direct.add(n);
        continue;
      }
      if (v.link || !v.version) continue;
      pkgs.push({ name: v.name ?? k.slice(k.lastIndexOf("node_modules/") + 13), version: v.version });
    }
  } else {
    const walkDeps = (deps) => {
      for (const [n, v] of Object.entries(deps ?? {})) {
        if (v.version && !/^(file|link):/.test(v.version)) pkgs.push({ name: n, version: v.version });
        walkDeps(v.dependencies);
      }
    };
    walkDeps(j.dependencies);
  }
  return { pkgs, direct };
}

function parsePnpmLock(text) {
  const pkgs = [];
  const direct = new Set();
  const v5 = /^lockfileVersion:\s*['"]?5/m.test(text);
  const stack = [];
  for (const line of text.split("\n")) {
    const m = line.match(/^( *)(?:'([^']+)'|"([^"]+)"|([^\s#'"-][^:]*?)):(?:\s|$)/);
    if (!m) continue;
    const indent = m[1].length;
    while (stack.length && stack.at(-1).indent >= indent) stack.pop();
    stack.push({ indent, key: m[2] ?? m[3] ?? m[4] });
    const p = stack.map((s) => s.key);
    if (p.length === 2 && p[0] === "packages") {
      const k = p[1].replace(/^\//, "");
      if (v5) {
        const i = k.lastIndexOf("/");
        if (i > 0) pkgs.push({ name: k.slice(0, i), version: k.slice(i + 1).split("_")[0] });
      } else {
        const base = k.replace(/\(.*$/, "");
        const i = base.lastIndexOf("@");
        if (i > 0) pkgs.push({ name: base.slice(0, i), version: base.slice(i + 1) });
      }
    } else if ((p.length === 4 && p[0] === "importers" && DEP_SECTIONS.has(p[2])) || (p.length === 2 && DEP_SECTIONS.has(p[0]))) {
      direct.add(p.at(-1));
    }
  }
  return { pkgs: pkgs.filter((x) => /^\d/.test(x.version)), direct };
}

function parseYarnLock(text) {
  const pkgs = [];
  let name = null;
  for (const line of text.split("\n")) {
    if (/^[^\s#].*:$/.test(line)) {
      const first = line.slice(0, -1).split(/,\s*/)[0].replace(/^"|"$/g, "");
      const at = first.indexOf("@", 1);
      name = at > 0 && first !== "__metadata" && !/^(workspace|link|file|portal):/.test(first.slice(at + 1)) ? first.slice(0, at) : null;
    } else if (name) {
      const m = line.match(/^\s+version:?\s+"?([^"\s]+)"?/);
      if (m) {
        pkgs.push({ name, version: m[1] });
        name = null;
      }
    }
  }
  return { pkgs, direct: new Set() };
}

function parseBunLock(text) {
  const j = JSON.parse(text.replace(/,(\s*[}\]])/g, "$1")); // JSONC trailing commas
  const direct = new Set();
  for (const w of Object.values(j.workspaces ?? {})) for (const s of DEP_SECTIONS) for (const n of Object.keys(w[s] ?? {})) direct.add(n);
  const pkgs = [];
  for (const v of Object.values(j.packages ?? {})) {
    const id = Array.isArray(v) ? v[0] : null;
    const i = id?.lastIndexOf("@") ?? -1;
    if (i > 0 && /^\d/.test(id.slice(i + 1))) pkgs.push({ name: id.slice(0, i), version: id.slice(i + 1) });
  }
  return { pkgs, direct };
}

// ---------- Python ----------

/** PEP 508 requirement -> { name, spec } (spec "" when unknown, e.g. a URL reference). */
function pep508(s) {
  const m = s.trim().match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(\(?[^;@]*\)?)?\s*(@)?/);
  if (!m) return null;
  return { name: m[1], spec: m[3] ? "" : (m[2] ?? "").replace(/[()\s]/g, "") };
}

function parseRequirements(text) {
  const reqs = [];
  for (const raw of text.replace(/\\\r?\n/g, " ").split("\n")) {
    const line = raw.replace(/\s#.*$/, "").replace(/^#.*$/, "").trim();
    if (!line || line.startsWith("-") || /^[a-z+]+:\/\//i.test(line)) continue;
    const r = pep508(line.split(/\s--hash/)[0]);
    if (r) reqs.push(r);
  }
  return reqs;
}

function parsePyproject(text) {
  const reqs = [];
  let python = null;
  let section = "";
  let collecting = false;
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\s#.*$/, "");
    const sec = line.match(/^\s*\[+([^\]]+)\]+\s*$/);
    if (sec && !collecting) {
      section = sec[1].trim().replace(/"/g, "");
      continue;
    }
    if (collecting) {
      for (const q of line.matchAll(/"([^"]+)"|'([^']+)'/g)) reqs.push(pep508(q[1] ?? q[2]));
      if (line.replace(/"[^"]*"|'[^']*'/g, "").includes("]")) collecting = false;
      continue;
    }
    const kv = line.match(/^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*)$/);
    if (!kv) continue;
    const [, key, value] = kv;
    const arraySection = section === "project" ? key === "dependencies" : section === "project.optional-dependencies" || section === "dependency-groups";
    if (arraySection && value.startsWith("[")) {
      for (const q of value.matchAll(/"([^"]+)"|'([^']+)'/g)) reqs.push(pep508(q[1] ?? q[2]));
      collecting = !value.replace(/"[^"]*"|'[^']*'/g, "").includes("]");
    } else if (section === "project" && key === "requires-python") {
      python = value.match(/["']([^"']+)["']/)?.[1] ?? null;
    } else if (/^tool\.poetry\.(dev-)?(group\.[^.]+\.)?dependencies$/.test(section)) {
      const spec = value.match(/^["']([^"']*)["']/)?.[1] ?? value.match(/version\s*=\s*["']([^"']*)["']/)?.[1] ?? "";
      if (key === "python") python = spec;
      else reqs.push({ name: key, spec: spec === "*" ? "" : spec });
    }
  }
  return { reqs: reqs.filter(Boolean), python };
}

/** poetry.lock / uv.lock: top-level [[package]] blocks with name/version at column 0. */
function parseTomlLock(text) {
  const pkgs = [];
  let cur = null;
  const flush = () => cur?.name && cur.version && !cur.local && pkgs.push({ name: cur.name, version: cur.version });
  for (const line of text.split("\n")) {
    if (line.startsWith("[[package]]")) {
      flush();
      cur = {};
    } else if (cur && line.startsWith("[")) {
      flush();
      cur = null;
    } else if (cur) {
      const m = line.match(/^(name|version)\s*=\s*"([^"]+)"/);
      if (m && !cur[m[1]]) cur[m[1]] = m[2];
      if (/^source\s*=\s*\{\s*(editable|virtual|directory)\s*=/.test(line)) cur.local = true;
    }
  }
  flush();
  return { pkgs, direct: new Set() };
}

function parsePipfileLock(text) {
  const j = JSON.parse(text);
  const pkgs = [];
  for (const s of ["default", "develop"])
    for (const [n, v] of Object.entries(j[s] ?? {})) if (typeof v.version === "string") pkgs.push({ name: n, version: v.version.replace(/^==/, "") });
  return { pkgs, direct: new Set() };
}

// ---------- Go, Rust, Ruby, PHP, Java, .NET ----------

function parseGoMod(text) {
  const pkgs = [];
  const direct = new Set();
  let go = null;
  let inRequire = false;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (/^go\s+\d/.test(line)) go = line.split(/\s+/)[1];
    if (/^require\s*\($/.test(line)) inRequire = true;
    else if (inRequire && line === ")") inRequire = false;
    const m = (inRequire ? line : line.replace(/^require\s+/, "")).match(/^([\w.~/-]+\.[\w.~/-]+)\s+(v[\w.+-]+)(\s*\/\/\s*indirect)?/);
    if (m && (inRequire || line.startsWith("require "))) {
      pkgs.push({ name: m[1], version: m[2] });
      if (!m[3]) direct.add(m[1]);
    }
  }
  return { pkgs, direct, go };
}

/** Cargo.lock: registry/git crates only (local workspace crates have no `source`). */
function parseCargoLock(text) {
  const pkgs = [];
  for (const block of text.split(/^\[\[package\]\]/m).slice(1)) {
    const get = (k) => block.match(new RegExp(`^${k}\\s*=\\s*"([^"]+)"`, "m"))?.[1];
    if (get("source") && get("name") && get("version")) pkgs.push({ name: get("name"), version: get("version") });
  }
  return { pkgs, direct: new Set() };
}

function cargoTomlDeps(text) {
  const names = [];
  let section = "";
  for (const line of text.split("\n")) {
    const sec = line.match(/^\s*\[([^\]]+)\]/);
    if (sec) section = sec[1];
    else if (/(^|\.)((dev|build)-)?dependencies$/.test(section)) {
      const m = line.match(/^\s*([A-Za-z0-9_-]+)\s*=/);
      if (m) names.push(m[1]);
    }
  }
  return names;
}

function parseGemfileLock(text) {
  const pkgs = [];
  const direct = new Set();
  let section = "";
  let ruby = null;
  for (const line of text.split("\n")) {
    if (/^\S/.test(line)) section = line.trim();
    const spec = line.match(/^ {4}([\w.-]+) \(([^)\s]+)\)$/); // 4 spaces = a gem; 6 = its dependencies
    if (spec && (section === "GEM" || section === "GIT")) pkgs.push({ name: spec[1], version: spec[2].split("-")[0] });
    const dep = section === "DEPENDENCIES" && line.match(/^ {2}([\w.-]+)/);
    if (dep) direct.add(dep[1]);
    const r = section === "RUBY VERSION" && line.match(/ruby (\d[\w.]*)/);
    if (r) ruby = r[1].replace(/p\d+$/, "");
  }
  return { pkgs, direct, ruby };
}

function parseComposerLock(text) {
  const j = JSON.parse(text);
  const pkgs = [...(j.packages ?? []), ...(j["packages-dev"] ?? [])].filter((p) => p.name && p.version).map((p) => ({ name: p.name, version: String(p.version).replace(/^v/, "") }));
  return { pkgs, direct: new Set() };
}

function parsePom(text) {
  const deps = [];
  const props = Object.fromEntries([...text.matchAll(/<([\w.-]+)>([^<${}]+)<\/\1>/g)].map((m) => [m[1], m[2].trim()]));
  for (const m of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const tag = (t) => m[1].match(new RegExp(`<${t}>\\s*([^<]+?)\\s*</${t}>`))?.[1];
    const [g, a] = [tag("groupId"), tag("artifactId")];
    let v = tag("version");
    if (v?.startsWith("${")) v = props[v.slice(2, -1)];
    if (g && a) deps.push({ name: `${g}:${a}`, spec: v && !v.includes("$") ? v : "" });
  }
  return deps;
}

function parseGradleLock(text) {
  const pkgs = [];
  for (const line of text.split("\n")) {
    const m = line.match(/^([\w.-]+):([\w.-]+):([^=\s]+)=/);
    if (m) pkgs.push({ name: `${m[1]}:${m[2]}`, version: m[3] });
  }
  return { pkgs, direct: new Set() };
}

const parseGradleBuild = (text) =>
  [...text.matchAll(/\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)\s*\(?\s*["']([\w.-]+):([\w.-]+):([^"'$]+)["']/g)].map((m) => ({ name: `${m[1]}:${m[2]}`, spec: m[3] }));

function parseNugetLock(text) {
  const pkgs = [];
  const direct = new Set();
  for (const deps of Object.values(JSON.parse(text).dependencies ?? {}))
    for (const [name, d] of Object.entries(deps)) {
      if (d.type === "Project" || !d.resolved) continue;
      pkgs.push({ name, version: d.resolved });
      if (d.type === "Direct") direct.add(name);
    }
  return { pkgs, direct };
}

function parseCsproj(text) {
  const refs = [...text.matchAll(/<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]*)")?/g)].map((m) => ({ name: m[1], spec: m[2] ?? "" }));
  const tf = text.match(/<TargetFrameworks?>\s*net(?:coreapp)?(\d+\.\d+)/)?.[1];
  return { refs, dotnet: tf ?? null };
}

// ---------- infrastructure as code ----------

const TF_RESOURCES = {
  aws_db_instance: ["aws", "rds", "engine", "engine_version"],
  aws_rds_cluster: ["aws", "rds", "engine", "engine_version"],
  aws_elasticache_cluster: ["aws", "elasticache", "engine", "engine_version"],
  aws_elasticache_replication_group: ["aws", "elasticache", "engine", "engine_version"],
  aws_memorydb_cluster: ["aws", "memorydb", "engine", "engine_version"],
  aws_eks_cluster: ["aws", "eks", null, "version", "kubernetes"],
  aws_opensearch_domain: ["aws", "opensearch", null, "engine_version", "opensearch"],
  aws_elasticsearch_domain: ["aws", "opensearch", null, "elasticsearch_version", "elasticsearch"],
  aws_mq_broker: ["aws", "mq", "engine_type", "engine_version"],
  aws_msk_cluster: ["aws", "kafka", null, "kafka_version", "kafka"],
  google_sql_database_instance: ["gcp", "cloudsql", null, "database_version"],
  google_container_cluster: ["gcp", "gke", null, "min_master_version", "kubernetes"],
  azurerm_postgresql_flexible_server: ["azure", "postgresql", null, "version", "postgres"],
  azurerm_kubernetes_cluster: ["azure", "aks", null, "kubernetes_version", "kubernetes"],
};

/** Terraform resources with literal engine versions (spec §5.3). A version from a variable is a gap (§8.2). */
function parseTerraform(text, rel) {
  const out = { components: [], gaps: [] };
  let cur = null;
  let depth = 0;
  text.split("\n").forEach((raw, i) => {
    // Braces inside comments or strings must not shift the block depth.
    const line = raw.replace(/("(?:[^"\\]|\\.)*")|(#|\/\/).*$/g, (m, str) => str ?? "");
    const start = depth === 0 && line.match(/^\s*resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{/);
    if (start && TF_RESOURCES[start[1]]) cur = { type: start[1], line: i + 1, attrs: {} };
    else if (cur && depth === 1) {
      const kv = line.match(/^\s*([\w]+)\s*=\s*(.+?)\s*$/);
      if (kv) cur.attrs[kv[1]] = kv[2];
    }
    const code = line.replace(/"(?:[^"\\]|\\.)*"/g, '""');
    depth = Math.max(0, depth + (code.match(/\{/g) ?? []).length - (code.match(/\}/g) ?? []).length);
    if (depth <= 0 && cur) {
      const [provider, service, engineKey, versionKey, fixedEngine] = TF_RESOURCES[cur.type];
      const lit = (v) => v?.match(/^"([^"$]*)"$/)?.[1];
      let engine = fixedEngine ?? lit(cur.attrs[engineKey])?.toLowerCase() ?? null;
      let version = lit(cur.attrs[versionKey]) ?? null;
      if (cur.type === "google_sql_database_instance" && version) [engine, version] = [version.split("_")[0].toLowerCase(), version.split("_").slice(1).join(".")];
      if (/^(opensearch|elasticsearch)$/.test(engine) && version?.includes("_")) version = version.split("_")[1];
      if (cur.attrs[versionKey] && !version) out.gaps.push({ id: `tf-var-${service}-${rel}:${cur.line}`, provider, reason: "version_from_variable", service });
      out.components.push({ type: "cloud_resource", provider, service, engine, version, locations: [`${rel}:${cur.line}`], provenance: prov("terraform", !!version) });
      cur = null;
      depth = 0;
    }
  });
  return out;
}

function parseTerraformLock(text) {
  return [...text.matchAll(/provider\s+"(?:registry\.terraform\.io\/)?([^"]+)"\s*\{[^}]*?version\s*=\s*"([^"]+)"/g)].map((m) => ({ name: m[1], version: m[2] }));
}

/** serverless.yml / SAM templates: function runtimes. */
function lambdaRuntimes(text, rel) {
  const out = [];
  text.split("\n").forEach((line, i) => {
    const m = line.match(/^\s*[Rr]untime:\s*["']?(nodejs|python|java|dotnet|ruby)(\d+(?:\.\d+)?)/);
    if (m) out.push({ type: "runtime", name: { nodejs: "node", python: "python", java: "java", dotnet: "dotnet", ruby: "ruby" }[m[1]], version: m[2], locations: [`${rel}:${i + 1}`], provenance: prov("lambda_runtime") });
  });
  return out;
}

// ---------- containers, CI, runtimes, services ----------

export function parseImageRef(ref) {
  const [main, digest = null] = ref.split("@");
  const slash = main.lastIndexOf("/");
  const colon = main.lastIndexOf(":");
  const hasTag = colon > slash;
  return { name: hasTag ? main.slice(0, colon) : main, tag: hasTag ? main.slice(colon + 1) : digest ? null : "latest", digest };
}

const OFFICIAL_RUNTIMES = { node: "node", python: "python", golang: "go", ruby: "ruby", php: "php", openjdk: "java", "eclipse-temurin": "java", "oven/bun": "bun", "denoland/deno": "deno", rust: "rust" };

function imageComponents(ref, location, method) {
  const img = parseImageRef(ref);
  if (img.name.includes("$")) return [];
  const out = [{ type: "container_image", name: img.name, tag: img.tag?.includes("$") ? null : img.tag, digest: img.digest, locations: [location], provenance: prov(method) }];
  const runtime = OFFICIAL_RUNTIMES[img.name.replace(/^(docker\.io\/)?(library\/)?/, "")];
  const version = img.tag?.match(/^v?(\d+(?:\.\d+)*)/)?.[1];
  if (runtime && version) out.push({ type: "runtime", name: runtime, version, locations: [location], provenance: prov("docker_base_image") });
  return out;
}

function parseDockerfile(text, rel) {
  const args = {};
  const stages = new Set();
  const out = [];
  text.split("\n").forEach((line, i) => {
    const arg = line.match(/^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=["']?([^"'\s]+)/i);
    if (arg) args[arg[1]] = arg[2];
    const from = line.match(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i);
    if (!from) return;
    const ref = from[1].replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}?/g, (m, n, def) => args[n] ?? def ?? m);
    const isStage = ref.toLowerCase() === "scratch" || stages.has(ref.toLowerCase()); // FROM <earlier stage>
    if (from[2]) stages.add(from[2].toLowerCase());
    if (!isStage) out.push(...imageComponents(ref, `${rel}:${i + 1}`, "dockerfile"));
  });
  return out;
}

function parseImageLines(text, rel, method) {
  const out = [];
  text.split("\n").forEach((line, i) => {
    const m = line.match(/^\s*(?:-\s*)?image:\s*["']?([^"'\s#]+)/);
    if (m) out.push(...imageComponents(m[1].replace(/\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}]*)\}/g, "$1"), `${rel}:${i + 1}`, method));
  });
  return out;
}

function parseWorkflow(text, rel) {
  const out = parseImageLines(text, rel, "workflow");
  text.split("\n").forEach((line, i) => {
    const m = line.match(/^\s*(?:-\s*)?uses:\s*["']?([^"'\s#]+)/);
    if (!m || m[1].startsWith("./")) return;
    if (m[1].startsWith("docker://")) return out.push(...imageComponents(m[1].slice(9), `${rel}:${i + 1}`, "workflow"));
    const [action, ref = null] = m[1].split("@");
    const name = action.split("/").slice(0, 2).join("/").toLowerCase();
    out.push({ type: "ci_action", name, ref, pinned_to_sha: /^[0-9a-f]{40}$/i.test(ref ?? ""), locations: [`${rel}:${i + 1}`], provenance: prov("workflow") });
  });
  return out;
}

function runtimeFiles(text, rel) {
  const base = path.basename(rel);
  const rt = (name, version) => (version ? [{ type: "runtime", name, version: version.replace(/^v(?=\d)/, ""), locations: [rel], provenance: prov("version_file") }] : []);
  if (base === ".nvmrc" || base === ".node-version") return rt("node", firstLine(text));
  if (base === ".python-version") return rt("python", firstLine(text));
  if (base === "runtime.txt") {
    const m = firstLine(text)?.match(/^([a-z]+)-(.+)$/);
    return m ? rt(m[1], m[2]) : [];
  }
  if (base === ".tool-versions")
    return text.split("\n").flatMap((l) => {
      const [tool, version] = l.trim().split(/\s+/);
      return RUNTIME_ALIASES[tool] && version ? rt(RUNTIME_ALIASES[tool], version) : [];
    });
  if (/mise\.toml$/.test(base)) {
    let inTools = false;
    return text.split("\n").flatMap((l) => {
      if (/^\s*\[/.test(l)) inTools = /^\s*\[tools\]/.test(l);
      const m = inTools && l.match(/^\s*["']?([a-z]+)["']?\s*=\s*\[?\s*["']([^"']+)["']/);
      return m && RUNTIME_ALIASES[m[1]] ? rt(RUNTIME_ALIASES[m[1]], m[2]) : [];
    });
  }
  return [];
}

/** Variable names only. Values are never read into the inventory. */
export function envNames(text) {
  return [...text.matchAll(/^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=/gm)].map((m) => m[1]);
}

// ---------- assemble ----------

const LOCKS = {
  "package-lock.json": ["npm", parseNpmLock],
  "npm-shrinkwrap.json": ["npm", parseNpmLock],
  "pnpm-lock.yaml": ["npm", parsePnpmLock],
  "yarn.lock": ["npm", parseYarnLock],
  "bun.lock": ["npm", parseBunLock],
  "poetry.lock": ["pypi", parseTomlLock],
  "uv.lock": ["pypi", parseTomlLock],
  "Pipfile.lock": ["pypi", parsePipfileLock],
  "go.mod": ["go", parseGoMod],
  "Cargo.lock": ["cargo", parseCargoLock],
  "Gemfile.lock": ["rubygems", parseGemfileLock],
  "composer.lock": ["packagist", parseComposerLock],
  "gradle.lockfile": ["maven", parseGradleLock],
  "packages.lock.json": ["nuget", parseNugetLock],
};

/** Nearest directory at or above `dir` that has a lockfile for this ecosystem. */
function coveringLock(locksByDir, eco, dir) {
  for (let d = dir; ; d = dirOf(d)) {
    if (locksByDir.has(`${eco}:${d}`)) return locksByDir.get(`${eco}:${d}`);
    if (!d) return null;
  }
}

/**
 * contents: Map<relPath, Buffer|string>. Returns { components, warnings }.
 * Lockfiles win over manifests: a manifest only contributes loose ranges when no lockfile covers its directory.
 */
export function detect(contents) {
  // Windows checkouts (core.autocrlf) use CRLF; every parser below is line-based.
  const text = new Map([...contents].map(([f, b]) => [f, b.toString("utf8").replace(/\r\n?/g, "\n")]));
  const components = [];
  const warnings = [];
  const envNamesSeen = [];
  const iacGaps = [];
  const safe = (rel, fn) => {
    try {
      return fn();
    } catch (e) {
      warnings.push(`${rel}: could not parse (${e.message.split("\n")[0]})`);
    }
  };

  // Locks first, so manifests know whether they're covered.
  const locksByDir = new Map();
  for (const [rel, t] of text) {
    const l = LOCKS[path.basename(rel)];
    if (!l) continue;
    const parsed = safe(rel, () => l[1](t));
    if (parsed) locksByDir.set(`${l[0]}:${dirOf(rel)}`, { rel, eco: l[0], ...parsed, direct: new Set([...parsed.direct].map((n) => normName(l[0], n))) });
  }
  if ([...text.keys()].some((f) => f.endsWith("bun.lockb"))) warnings.push("bun.lockb is binary; run `bun install --save-text-lockfile` to get exact versions");

  for (const [rel, t] of text) {
    const base = path.basename(rel);
    const dir = dirOf(rel);
    let manifest = null; // { eco, reqs: [{name, spec}] }
    if (base === "package.json") {
      const pj = safe(rel, () => parsePackageJson(t));
      if (!pj) continue;
      manifest = { eco: "npm", reqs: Object.entries(pj.deps).map(([name, spec]) => ({ name, spec: String(spec) })) };
      if (pj.node) components.push({ type: "runtime", name: "node", version: pj.node, locations: [`${rel}#engines`], provenance: prov("package_engines", false) });
    } else if (base === "pyproject.toml") {
      const pp = safe(rel, () => parsePyproject(t));
      if (!pp) continue;
      manifest = { eco: "pypi", reqs: pp.reqs };
      if (pp.python) components.push({ type: "runtime", name: "python", version: pp.python, locations: [`${rel}#requires-python`], provenance: prov("pyproject", false) });
    } else if (/^requirements[^/]*\.txt$/.test(base)) {
      const reqs = safe(rel, () => parseRequirements(t)) ?? [];
      const covered = coveringLock(locksByDir, "pypi", dir);
      for (const r of reqs) {
        const exact = exactVersion("pypi", r.spec);
        if (exact) components.push({ type: "package", ecosystem: "pypi", name: r.name, version: exact, version_spec: safeSpec(r.spec), direct: true, purl: purl("pypi", r.name, exact), locations: [rel], provenance: prov("requirements") });
        else if (!covered) components.push({ type: "package", ecosystem: "pypi", name: r.name, version: null, version_spec: safeSpec(r.spec), direct: true, loose_range: true, locations: [rel], provenance: prov("manifest", false) });
      }
      if (covered) reqs.forEach((r) => covered.direct.add(normName("pypi", r.name)));
    } else if (base === "Cargo.toml") {
      manifest = { eco: "cargo", reqs: (safe(rel, () => cargoTomlDeps(t)) ?? []).map((name) => ({ name, spec: "" })) };
    } else if (base === "composer.json") {
      const j = safe(rel, () => JSON.parse(t)) ?? {};
      const req = { ...j.require, ...j["require-dev"] };
      manifest = { eco: "packagist", reqs: Object.entries(req).filter(([n]) => n.includes("/")).map(([name, spec]) => ({ name, spec: String(spec) })) };
      if (req.php) components.push({ type: "runtime", name: "php", version: String(req.php), locations: [`${rel}#require.php`], provenance: prov("composer", false) });
    } else if (base === "pom.xml") {
      manifest = { eco: "maven", reqs: safe(rel, () => parsePom(t)) ?? [] };
    } else if (/^build\.gradle(\.kts)?$/.test(base)) {
      manifest = { eco: "maven", reqs: safe(rel, () => parseGradleBuild(t)) ?? [] };
    } else if (base.endsWith(".csproj")) {
      const cs = safe(rel, () => parseCsproj(t));
      if (!cs) continue;
      manifest = { eco: "nuget", reqs: cs.refs };
      if (cs.dotnet) components.push({ type: "runtime", name: "dotnet", version: cs.dotnet, locations: [rel], provenance: prov("csproj") });
    } else if (/^rust-toolchain(\.toml)?$/.test(base)) {
      const v = t.match(/channel\s*=\s*"([^"]+)"/)?.[1] ?? firstLine(t);
      if (v && /^\d/.test(v)) components.push({ type: "runtime", name: "rust", version: v, locations: [rel], provenance: prov("version_file") });
    } else if (base.endsWith(".tf")) {
      const tf = safe(rel, () => parseTerraform(t, rel));
      if (tf) components.push(...tf.components), iacGaps.push(...tf.gaps);
    } else if (base === ".terraform.lock.hcl") {
      for (const p of safe(rel, () => parseTerraformLock(t)) ?? [])
        components.push({ type: "package", ecosystem: "terraform", name: p.name, version: p.version, version_spec: p.version, direct: true, locations: [rel], provenance: prov("lockfile") });
    } else if (/^serverless\.ya?ml$/.test(base) || (/^template\.ya?ml$/.test(base) && /AWSTemplateFormatVersion|AWS::Serverless/.test(t))) {
      components.push(...lambdaRuntimes(t, rel));
      if (/^\s*name:\s*aws\b/m.test(t) || base.startsWith("template")) components.push({ type: "service", vendor: "aws", evidence: [`file:${rel}`], provenance: prov("service_mapping") });
    } else if (/Dockerfile|\.dockerfile$/i.test(base)) {
      components.push(...(safe(rel, () => parseDockerfile(t, rel)) ?? []));
    } else if (/^(docker-)?compose[^/]*\.ya?ml$/.test(base)) {
      components.push(...(safe(rel, () => parseImageLines(t, rel, "compose")) ?? []));
    } else if (rel.startsWith(".github/workflows/")) {
      components.push(...(safe(rel, () => parseWorkflow(t, rel)) ?? []));
    } else if (/^\.env\.(example|sample|template)$/.test(base)) {
      for (const n of envNames(t)) {
        envNamesSeen.push(n);
        const vendor = serviceForEnv(n);
        if (vendor) components.push({ type: "service", vendor, evidence: [`env_name:${n}`], provenance: prov("service_mapping") });
      }
    } else if (serviceForFile(base)) {
      components.push({ type: "service", vendor: serviceForFile(base), evidence: [`file:${rel}`], provenance: prov("service_mapping") });
      // Platform configs pin runtimes and images too.
      for (const [, name, v] of t.matchAll(/^\s*(NODE|PYTHON)_VERSION\s*=\s*"?([\d.]+)/gm))
        components.push({ type: "runtime", name: name === "NODE" ? "node" : "python", version: v, locations: [rel], provenance: prov("platform_config") });
      const image = base === "fly.toml" && t.match(/^\s*image\s*=\s*["']([^"']+)["']/m)?.[1];
      if (image) components.push(...imageComponents(image, rel, "platform_config"));
    } else {
      components.push(...runtimeFiles(t, rel));
    }

    if (manifest) {
      const covered = coveringLock(locksByDir, manifest.eco, dir);
      if (covered) manifest.reqs.forEach((r) => covered.direct.add(normName(manifest.eco, r.name)));
      else
        for (const r of manifest.reqs) {
          const exact = exactVersion(manifest.eco, r.spec);
          components.push({ type: "package", ecosystem: manifest.eco, name: r.name, version: exact ?? null, version_spec: safeSpec(r.spec), direct: true, loose_range: !exact, purl: purl(manifest.eco, r.name, exact), locations: [rel], provenance: prov("manifest", !!exact) });
        }
    }
  }

  for (const lock of locksByDir.values()) {
    if (lock.go) components.push({ type: "runtime", name: "go", version: lock.go, locations: [`${lock.rel}#go`], provenance: prov("go_mod") });
    if (lock.ruby) components.push({ type: "runtime", name: "ruby", version: lock.ruby, locations: [`${lock.rel}#ruby`], provenance: prov("gemfile_lock") });
  }
  for (const lock of locksByDir.values())
    for (const p of lock.pkgs.filter((x) => typeof x.name === "string" && typeof x.version === "string")) {
      // Git/URL "versions" (old npm lockfiles) aren't versions and may embed credentials.
      const version = /^v?\d/.test(p.version) ? p.version : null;
      components.push({ type: "package", ecosystem: lock.eco, name: p.name, version, version_spec: version ? (lock.eco === "pypi" ? `==${version}` : version) : safeSpec(p.version), direct: lock.direct.has(normName(lock.eco, p.name)), loose_range: !version || undefined, purl: purl(lock.eco, p.name, version), locations: [lock.rel], provenance: prov("lockfile", !!version) });
    }

  // Services implied by packages.
  for (const c of components.filter((c) => c.type === "package")) {
    const vendor = serviceForPackage(c.ecosystem, c.name);
    if (vendor && c.direct) components.push({ type: "service", vendor, evidence: [`package:${c.name}`], provenance: prov("service_mapping") });
  }
  return { components: merge(components), warnings, envNames: new Set(envNamesSeen), gaps: iacGaps };
}

// ---------- gaps (spec §8.2): things we know exist but can't fully describe ----------

export const SERVER_IMAGES = {
  postgresql: ["postgres", "postgis/postgis", "bitnami/postgresql"],
  redis: ["redis", "valkey/valkey", "bitnami/redis"],
  mysql: ["mysql", "mariadb", "bitnami/mysql"],
  mongodb: ["mongo", "bitnami/mongodb"],
  elasticsearch: ["elasticsearch", "opensearchproject/opensearch", "docker.elastic.co/elasticsearch/elasticsearch"],
  kafka: ["apache/kafka", "confluentinc/cp-kafka", "bitnami/kafka"],
  rabbitmq: ["rabbitmq"],
};
const CLOUD_ENGINES = {
  postgresql: ["postgres", "aurora-postgresql"],
  redis: ["redis", "valkey"],
  mysql: ["mysql", "aurora-mysql", "mariadb"],
  mongodb: ["docdb", "mongodb"],
  elasticsearch: ["opensearch", "elasticsearch"],
  kafka: ["kafka"],
  rabbitmq: ["rabbitmq"],
};
// Only Terraform is parsed for resources; cdk.json / serverless / SAM files don't tell us what exists.
const IAC = /(^|\/)[^/]+\.tf$/;

/** Deterministic gap rules over the finished component list (repo + cloud + manual). */
export function detectGaps(components, files, envNames = new Set(), scanned = new Set()) {
  const vendors = new Set(components.filter((c) => c.type === "service").map((c) => c.vendor));
  const gaps = [];
  const cloud = (provider) => components.some((c) => c.type === "cloud_resource" && c.provider === ({ "google-cloud": "gcp" }[provider] ?? provider));
  if (vendors.has("aws") && !files.some((f) => IAC.test(f)) && !cloud("aws") && !scanned.has("aws")) gaps.push({ id: "aws-resources", provider: "aws", reason: "aws_used_no_iac" });
  for (const [vendor, images] of Object.entries(SERVER_IMAGES)) {
    if (!vendors.has(vendor)) continue;
    const known = components.some(
      (c) => (c.type === "container_image" && images.includes(normImage(c.name))) || (c.type === "cloud_resource" && CLOUD_ENGINES[vendor].includes(c.engine)),
    );
    if (!known) gaps.push({ id: `${vendor}-version`, provider: vendor, reason: "server_version_unknown" });
  }
  if (envNames.has("DATABASE_URL") && !["postgresql", "mysql", "mongodb", "supabase", "neon", "planetscale"].some((v) => vendors.has(v)))
    gaps.push({ id: "database-provider", provider: "database", reason: "database_provider_unknown" });
  for (const p of ["google-cloud", "azure"]) if (vendors.has(p) && !cloud(p) && !scanned.has(p)) gaps.push({ id: `${p}-resources`, provider: p, reason: "provider_used_no_scanner" });
  return gaps;
}

/** Collapse duplicates (same thing found in several files), keeping every location and piece of evidence. */
function merge(components) {
  const byKey = new Map();
  for (const c of components) {
    const id = c.type === "service" ? `service:${c.vendor}` : [c.type, c.ecosystem, c.ecosystem ? normName(c.ecosystem, c.name) : c.name, c.provider, c.service, c.engine, c.version, c.version ? "" : c.version_spec, c.tag, c.digest, c.ref].join("|");
    const prev = byKey.get(id);
    if (!prev) byKey.set(id, { ...c });
    else {
      if (c.locations) prev.locations = [...new Set([...(prev.locations ?? []), ...c.locations])];
      if (c.evidence) prev.evidence = [...new Set([...prev.evidence, ...c.evidence])];
      if (c.direct) prev.direct = true;
    }
  }
  return [...byKey.values()];
}
