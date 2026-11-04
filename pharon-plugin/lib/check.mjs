// Local, read-only incident check (spec §13). The incident file only says *what* to look for;
// every check below is fixed code in this file. Nothing here executes, deletes or modifies anything,
// and Python is never run (a malicious .pth file would execute on interpreter start).
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, existsSync, openSync, readdirSync, readFileSync, readSync, statSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { affected, componentLevel, globMatch, normImage, normName } from "./match.mjs";
import { verifyDoc } from "./feedsig.mjs";
import { detect, envNames, isStackFile, listStackFiles, readStack } from "./detect.mjs";
import { git } from "./git.mjs";

/** Throws unless the incident carries a valid signature from a trusted feed key (see feedsig.mjs). */
export const verifyIncident = (doc, keys) => verifyDoc(doc, keys, "incident");

// "unknown" outranks "not_affected": a check that could not run must not read as all-clear.
const RANK = { not_affected: 0, unknown: 1, likely: 2, confirmed: 3 };
const worst = (a, b) => (RANK[b] > RANK[a] ? b : a);
const LEVEL_TO_VERDICT = { direct: "confirmed", likely: "likely", possible: "not_affected" };
const HOME = homedir();

function ls(dir) {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

/** Expand a pattern like "lib/python*\/site-packages" one directory level at a time (no recursion, no reads). */
function expand(base, pattern) {
  let paths = [base];
  for (const seg of pattern.split("/").filter(Boolean)) {
    if (seg === "..") return [];
    paths = seg.includes("*") ? paths.flatMap((p) => ls(p).filter((e) => globMatch(seg, e)).map((e) => path.join(p, e))) : paths.map((p) => path.join(p, seg)).filter(existsSync);
  }
  return paths;
}

function sitePackagesDirs(root) {
  const envs = [".venv", "venv", "env", ".env"].map((d) => path.join(root, d));
  if (process.env.VIRTUAL_ENV) envs.push(process.env.VIRTUAL_ENV);
  const repoName = path.basename(root).toLowerCase();
  for (const cache of [path.join(HOME, "Library/Caches/pypoetry/virtualenvs"), path.join(HOME, ".cache/pypoetry/virtualenvs")])
    envs.push(...ls(cache).filter((e) => e.toLowerCase().startsWith(repoName)).map((e) => path.join(cache, e)));
  const dirs = envs.flatMap((e) => expand(e, "lib/python*/site-packages"));
  dirs.push(
    ...expand(HOME, ".local/lib/python*/site-packages"),
    ...expand(HOME, "Library/Python/*/lib/python/site-packages"),
    ...expand(HOME, ".pyenv/versions/*/lib/python*/site-packages"),
    ...expand(HOME, ".local/share/uv/python/*/lib/python*/site-packages"),
    ...expand("/usr/local", "lib/python*/site-packages"),
    ...expand("/opt/homebrew", "lib/python*/site-packages"),
  );
  return [...new Set(dirs)];
}

function nodeModulesDirs(root, stackFiles) {
  const dirs = new Set(stackFiles.filter((f) => f.endsWith("package.json")).map((f) => path.join(root, path.dirname(f), "node_modules")));
  dirs.add(path.join(root, "node_modules"));
  for (const g of ["/usr/local/lib/node_modules", "/opt/homebrew/lib/node_modules"]) dirs.add(g);
  for (const d of expand(HOME, ".nvm/versions/node/*/lib/node_modules")) dirs.add(d);
  return [...dirs].filter(existsSync);
}

const mtime = (p) => {
  try {
    return statSync(p).mtime.toISOString();
  } catch {
    return null;
  }
};
const inWindow = (iso, w) => !!(iso && w?.start && iso >= w.start && (!w.end || iso <= w.end));
let ROOT = "";
// Labels: repo-relative inside the repo, ~/… under home.
const rel = (p) => (ROOT && p.startsWith(`${ROOT}/`) ? p.slice(ROOT.length + 1) : p.startsWith(HOME) ? `~${p.slice(HOME.length)}` : p);

/** Installed Python distributions (site-packages/*.dist-info) and Node packages (node_modules/<pkg>/package.json). */
function installedChecks(root, stackFiles, affects, window, add) {
  const pypi = affects.filter((a) => a.kind === "package" && a.ecosystem === "pypi");
  const npm = affects.filter((a) => a.kind === "package" && a.ecosystem === "npm");
  if (pypi.length)
    for (const sp of sitePackagesDirs(root)) {
      const label = `env: ${rel(sp.replace(/\/lib\/python[^/]*\/site-packages$/, ""))}`;
      for (const entry of ls(sp)) {
        const m = entry.match(/^(.+?)-([^-]+)\.(dist-info|egg-info)$/);
        if (!m) continue;
        for (const a of pypi) {
          if (normName("pypi", m[1]) !== normName("pypi", a.name)) continue;
          const level = componentLevel({ type: "package", ecosystem: "pypi", name: m[1], version: m[2] }, a);
          const at = mtime(path.join(sp, entry));
          add(label, "environment", LEVEL_TO_VERDICT[level], `${a.name} ${m[2]} installed${at ? ` (${at.slice(0, 16).replace("T", " ")} UTC${inWindow(at, window) ? ", during the exposure window" : ""})` : ""}`);
        }
      }
    }
  if (npm.length)
    for (const nm of nodeModulesDirs(root, stackFiles)) {
      const label = `env: ${rel(nm)}`;
      for (const a of npm) {
        const pj = path.join(nm, a.name, "package.json");
        if (existsSync(pj)) {
          let version = null;
          try {
            version = JSON.parse(readFileSync(pj, "utf8")).version;
          } catch {}
          const level = componentLevel({ type: "package", ecosystem: "npm", name: a.name, version }, a);
          add(label, "environment", LEVEL_TO_VERDICT[level], `${a.name} ${version} installed (${mtime(pj)?.slice(0, 10) ?? "?"})`);
        }
        // pnpm's virtual store keeps every installed version: node_modules/.pnpm/<name>@<version>
        const prefix = `${a.name.replace("/", "+")}@`;
        for (const e of ls(path.join(nm, ".pnpm")).filter((e) => e.startsWith(prefix))) {
          const version = e.slice(prefix.length).split(/[_(]/)[0];
          const level = componentLevel({ type: "package", ecosystem: "npm", name: a.name, version }, a);
          add(label, "environment", LEVEL_TO_VERDICT[level], `${a.name} ${version} in the pnpm store`);
        }
      }
    }
}

/** Indicator files: existence only. Pattern roots: site-packages/, node_modules/, ~/, otherwise repo-relative. */
function indicatorChecks(root, stackFiles, files, add) {
  for (const f of files ?? []) {
    const [head, ...rest] = String(f.pattern).split("/");
    const tail = rest.join("/");
    const bases = head === "site-packages" ? sitePackagesDirs(root) : head === "node_modules" ? nodeModulesDirs(root, stackFiles) : head === "~" ? [HOME] : [root];
    const pattern = head === "site-packages" || head === "node_modules" || head === "~" ? tail : f.pattern;
    for (const base of bases)
      for (const hit of expand(base, pattern).slice(0, 20)) add(`indicator: ${rel(hit)}`, "environment", "confirmed", `${f.description ?? "indicator file"} present (not opened)`);
  }
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const CACHE_HOME = process.platform === "darwin" ? path.join(HOME, "Library/Caches") : process.env.XDG_CACHE_HOME ?? path.join(HOME, ".cache");
const PNPM_STORES = [path.join(HOME, "Library/pnpm/store"), path.join(HOME, ".local/share/pnpm/store"), process.env.PNPM_HOME && path.join(process.env.PNPM_HOME, "store")].filter(Boolean);

function head(file, bytes = 400) {
  const fd = openSync(file, "r");
  try {
    const buf = Buffer.alloc(bytes);
    return buf.subarray(0, readSync(fd, buf, 0, bytes, 0)).toString("utf8");
  } finally {
    closeSync(fd);
  }
}

/**
 * Package caches: was an affected artifact downloaded on this machine? Mostly file-name checks.
 * A cached artifact is "likely", not "confirmed": downloaded doesn't prove it was installed or run.
 */
function cacheChecks(root, affects, add, manual) {
  const hit = (cache, a, version, p) =>
    affected(version, a) && add(`cache: ${cache}`, "environment", "likely", `${a.name} ${version} was downloaded on this machine (${rel(p)}, ${mtime(p)?.slice(0, 10) ?? "?"})`);
  const scan = (cache, a, dirs, re) => {
    for (const d of dirs) for (const e of ls(d)) {
      const m = e.match(re);
      if (m) hit(cache, a, m[1], path.join(d, e));
    }
  };

  for (const a of affects.filter((x) => x.kind === "package" && x.ecosystem === "npm")) {
    const base = a.name.split("/").pop();
    const dashed = a.name.replace("/", "-");
    // npm's cacache: the index file path is sha256 of the request key, so exact versions are an O(1) lookup.
    const npmCache = process.env.npm_config_cache ?? path.join(HOME, ".npm");
    for (const v of a.versions ?? []) {
      const h = createHash("sha256").update(`make-fetch-happen:request-cache:https://registry.npmjs.org/${a.name}/-/${base}-${v}.tgz`).digest("hex");
      const p = path.join(npmCache, "_cacache/index-v5", h.slice(0, 2), h.slice(2, 4), h.slice(4));
      if (existsSync(p)) hit("npm", a, v, p);
    }
    for (const store of PNPM_STORES) {
      scan("pnpm", a, expand(store, "v10/index/*"), new RegExp(`^[0-9a-f]+-${esc(a.name.replace("/", "+"))}@(\\d.*)\\.json$`));
      for (const f of expand(store, "v3/files/*").flatMap((d) => ls(d).filter((e) => e.endsWith("-index.json")).map((e) => path.join(d, e))).slice(0, 100_000)) {
        const m = head(f).match(/^\{"name":"([^"]+)","version":"([^"]+)"/);
        if (m && m[1] === a.name) hit("pnpm", a, m[2], f);
      }
    }
    scan("yarn", a, [path.join(CACHE_HOME, process.platform === "darwin" ? "Yarn/v6" : "yarn/v6")], new RegExp(`^npm-${esc(dashed)}-(\\d.*)-[0-9a-f]{40}-integrity$`));
    scan("yarn", a, [path.join(HOME, ".yarn/berry/cache"), path.join(root, ".yarn/cache")], new RegExp(`^${esc(dashed)}-npm-(\\d.*)-[0-9a-f]+-\\d+\\.zip$`));
    scan("bun", a, [path.join(HOME, ".bun/install/cache", a.name.includes("/") ? a.name.split("/")[0] : "")], new RegExp(`^${esc(base)}@(\\d[^@]*)@`));
  }

  const pypi = affects.filter((x) => x.kind === "package" && x.ecosystem === "pypi");
  for (const a of pypi) {
    const n = esc(normName("pypi", a.name).replace(/-/g, "_"));
    const uv = process.env.UV_CACHE_DIR ?? path.join(process.env.XDG_CACHE_HOME ?? path.join(HOME, ".cache"), "uv");
    scan("uv", a, expand(uv, "archive-v0/*"), new RegExp(`^${n}-(\\d[^-]*)\\.dist-info$`, "i"));
    const pip = process.env.PIP_CACHE_DIR ?? path.join(CACHE_HOME, "pip");
    scan("pip", a, expand(pip, "wheels/*/*/*/*"), new RegExp(`^${n}-(\\d[^-]*)-.*\\.whl$`, "i"));
  }
  if (pypi.length && existsSync(path.join(process.env.PIP_CACHE_DIR ?? path.join(CACHE_HOME, "pip"), "http-v2")))
    manual.push("pip's download cache is keyed by URL hash and can't be searched by package name. Treat it as possibly containing the affected version.");
}

function dockerChecks(affects, add, manual) {
  const imgs = affects.filter((a) => a.kind === "container_image");
  if (!imgs.length) return;
  let out;
  try {
    out = execFileSync("docker", ["images", "--no-trunc", "--digests", "--format", "{{json .}}"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 8000 });
  } catch {
    manual.push(`Docker isn't available here, so local images weren't checked. On machines that run containers, look for: ${imgs.map((a) => `${a.name}:${(a.tags ?? ["*"]).join("|")}`).join(", ")}`);
    return add("docker: local images", "image", "unknown", "docker not available");
  }
  let seen = false;
  for (const line of out.split("\n").filter(Boolean)) {
    const i = JSON.parse(line);
    for (const a of imgs) {
      if (normImage(i.Repository) !== normImage(a.name)) continue;
      seen = true;
      const level = componentLevel({ type: "container_image", name: i.Repository, tag: i.Tag, digest: i.Digest !== "<none>" ? i.Digest : null }, a);
      add(`docker: ${i.Repository}:${i.Tag}`, "image", LEVEL_TO_VERDICT[level], `local image ${i.ID.slice(7, 19)} created ${i.CreatedAt}`);
    }
  }
  if (!seen) add("docker: local images", "image", "not_affected", "no local image of the affected repositories");
}

/** Lockfile state at the start of the exposure window and every lockfile commit inside it. */
function historyChecks(root, affects, window, add) {
  if (!window?.start) return;
  const commits = new Set();
  const atStart = git(root, ["rev-list", "-1", `--before=${window.start}`, "HEAD"]);
  if (atStart) commits.add(atStart);
  const during = git(root, ["log", `--since=${window.start}`, ...(window.end ? [`--until=${window.end}`] : []), "--format=%H", "-n", "50", "HEAD"]);
  for (const c of during?.split("\n").filter(Boolean) ?? []) commits.add(c);
  for (const sha of commits) {
    const files = git(root, ["ls-tree", "-r", "--name-only", sha])?.split("\n").filter((f) => isStackFile(f) && /lock|requirements|package\.json|pyproject/.test(f)) ?? [];
    const contents = new Map();
    for (const f of files) {
      const t = git(root, ["show", `${sha}:${f}`], { raw: true });
      if (t !== null) contents.set(f, t);
    }
    const date = git(root, ["show", "-s", "--format=%cI", sha]);
    for (const c of detect(contents).components)
      for (const a of affects)
        if (componentLevel(c, a) === "direct") add(`repo history: ${c.locations[0]}`, "repo", "confirmed", `${c.name} ${c.version} was in commit ${sha.slice(0, 8)} (${date})`);
  }
}

const TARGET_ENV = {
  cloud_credentials: /^(AWS_|AZURE_|GOOGLE_APPLICATION_CREDENTIALS|GCP_|GCLOUD_|DIGITALOCEAN_|DO_TOKEN|HCLOUD_)/,
  ai_api_keys: /(OPENAI|ANTHROPIC|GEMINI|GOOGLE_API|MISTRAL|GROQ|COHERE|HF_|HUGGINGFACE|REPLICATE|TOGETHER|PERPLEXITY|DEEPSEEK|XAI|LITELLM|OPENROUTER)\w*(KEY|TOKEN)/,
  package_registry_tokens: /^(NPM_TOKEN|NODE_AUTH_TOKEN|PYPI_|TWINE_|POETRY_PYPI_|UV_PUBLISH_TOKEN|GEM_HOST_API_KEY|CARGO_REGISTRY_TOKEN|DOCKERHUB_|DOCKER_PASSWORD)/,
  github_tokens: /^(GITHUB_TOKEN|GH_TOKEN|GH_PAT|GITHUB_PAT)/,
  database_credentials: /^(DATABASE_URL|POSTGRES_|PG(PASSWORD|USER)|MYSQL_|MONGO(DB)?_|REDIS_)/,
  platform_tokens: /^(VERCEL_TOKEN|NETLIFY_AUTH_TOKEN|FLY_API_TOKEN|RAILWAY_TOKEN|RENDER_API_KEY|HEROKU_API_KEY|CLOUDFLARE_API_TOKEN|SUPABASE_ACCESS_TOKEN)/,
  environment_variables: /./,
};
const TARGET_FILES = {
  ssh_keys: ["~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa"],
  cloud_credentials: ["~/.aws/credentials", "~/.config/gcloud/application_default_credentials.json", "~/.azure/msal_token_cache.json", "~/.kube/config"],
  package_registry_tokens: ["~/.npmrc", "~/.pypirc", "~/.docker/config.json"],
  github_tokens: ["~/.config/gh/hosts.yml", "~/.git-credentials"],
};

/** Secret NAMES (never values) that the incident's targets put at risk. */
function rotationList(root, stackFiles, targets) {
  const sources = new Map(); // name -> Set(where)
  const note = (name, where) => sources.set(name, (sources.get(name) ?? new Set()).add(where));
  for (const f of stackFiles.filter((f) => /\.env\.(example|sample|template)$/.test(f))) for (const n of envNames(readFileSync(path.join(root, f), "utf8"))) note(n, f);
  for (const f of stackFiles.filter((f) => f.startsWith(".github/workflows/")))
    for (const m of readFileSync(path.join(root, f), "utf8").matchAll(/secrets\.([A-Za-z_][A-Za-z0-9_]*)/g)) note(m[1], `${f} (CI secret)`);
  for (const n of Object.keys(process.env)) note(n, "your shell environment");

  const out = [];
  for (const [name, where] of sources)
    for (const t of targets ?? []) {
      const re = TARGET_ENV[t];
      // The catch-all target only covers names the project declares, not every shell variable.
      const w = [...where].filter((x) => t !== "environment_variables" || x !== "your shell environment");
      if (re && w.length && re.test(name)) {
        out.push({ name, target: t, found_in: w });
        break;
      }
    }
  for (const t of targets ?? []) for (const f of TARGET_FILES[t] ?? []) if (existsSync(f.replace("~", HOME))) out.push({ name: f, target: t, found_in: ["this machine"] });
  return out;
}

function describe(c, level) {
  if (c.type === "service") return `uses ${c.vendor} (${c.evidence.join(", ")})`;
  if (c.version) return `${c.name} ${c.version}${level === "possible" ? " (not an affected version)" : ""}`;
  return `${c.name} ${c.version_spec || "(any version)"}${level === "likely" ? " is a loose range that could resolve to an affected version" : ""}`;
}

/**
 * Run every check for one verified incident. Returns plain JSON for the check-incident skill. `services` are the ones
 * the team confirmed in setup (link.inferred): no file scan finds them, but the dashboard matches them.
 */
export function runCheck(root, doc, keyId, services = []) {
  ROOT = root;
  const affects = doc.affects ?? [];
  const window = doc.exposure_window;
  const locations = new Map();
  const manual = [];
  const add = (label, kind, verdict, evidence) => {
    const l = locations.get(label) ?? { label, kind, verdict, evidence: [] };
    l.verdict = worst(l.verdict, verdict);
    l.evidence.push(evidence);
    locations.set(label, l);
  };

  const stackFiles = listStackFiles(root);
  const confirmed = services.map((s) => ({ type: "service", vendor: s.vendor, evidence: s.evidence ?? [], locations: ["services confirmed in setup"] }));
  for (const c of [...detect(readStack(root, stackFiles)).components, ...confirmed])
    for (const a of affects) {
      const level = componentLevel(c, a);
      if (level) add(`repo: ${c.locations?.[0] ?? "service mapping"}`, "repo", LEVEL_TO_VERDICT[level], describe(c, level));
    }
  historyChecks(root, affects, window, add);
  installedChecks(root, stackFiles, affects, window, add);
  indicatorChecks(root, stackFiles, doc.indicators?.files, add);
  cacheChecks(root, affects, add, manual);
  dockerChecks(affects, add, manual);
  if (affects.some((a) => a.kind === "service" || a.kind === "cloud_resource"))
    manual.push("This incident concerns a hosted service: check the vendor's notice and your account's audit/access logs; local files can't prove exposure.");

  const list = [...locations.values()];
  const verdict = list.reduce((v, l) => worst(v, l.verdict), "not_affected");
  return {
    incident: { id: doc.id, title: doc.title, type: doc.type, severity: doc.severity, summary: doc.summary, published_at: doc.published_at, exposure_window: window, targets: doc.targets ?? [], remediation: doc.remediation ?? [], references: doc.references ?? [] },
    signature: { valid: true, key_id: keyId },
    verdict,
    locations: list.sort((a, b) => RANK[b.verdict] - RANK[a.verdict]),
    rotate: rotationList(root, stackFiles, doc.targets),
    rotate_now: verdict === "confirmed" || verdict === "likely",
    manual_checks: manual,
  };
}
