import { spawn } from "node:child_process";
import { appendFileSync, closeSync, openSync, rmSync, statSync } from "node:fs";
import { hostname } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import * as cfg from "./config.mjs";
import { detect, detectGaps, fingerprint, isStackFile, listStackFiles, readStack } from "./detect.mjs";
import { accountRef, awsStatus, otherTools, scanAws } from "./cloud.mjs";
import { azureStatus, gcpStatus, scanAzure, scanGcp } from "./cloud-other.mjs";
import { feedKeys, verifyDoc } from "./feedsig.mjs";
import { changedPaths, git, normalizeRemote, repoDetails } from "./git.mjs";
import { redact, validPattern } from "./redact.mjs";
import { gapText, SERVICE_MAP_VERSION, setServiceMap } from "./services.mjs";

const HELP = `pharon ${cfg.VERSION}: the warning light for your stack

Usage:
  pharon login [--api <url>]        Log in (device code; token goes to your OS keychain)
  pharon link [--name <n>]          Link this repo to your org (identity from the git remote)
  pharon show [--json]              Show exactly what would be uploaded
  pharon sync [--yes] [--force] [--cloud aws|gcp|azure|all]   Upload the inventory if the stack changed (--cloud: scan now)
  pharon status [--json]            Last sync, queue, open incidents for this repo
  pharon check <incident-id> [--json] [--report]  Check locally whether you're affected (read-only);
                                    --report shares verdicts + secret names (never values) with the team
  pharon queue flush                Retry queued uploads
  pharon notices [--json]           What needs attention in this repo (also shown at session start)
  pharon ci sync | pharon ci check [--fail-on high] [--comment]
                                    CI mode with a CI token (PHARON_TOKEN): upload, or check a pull request
  pharon gaps [--json]              What Pharon can't fully see yet, and which tools could fill it
  pharon track <provider> <cloud_cli|manual|skip> [--profile p | --project id | --subscription s]
                                    How the team tracks a provider (aws, google-cloud, azure, …)
  pharon manual add <provider> <service> <engine> <version> | list | confirm <id> | update <id> <version>
  pharon services add <vendor> --evidence host:<h>|file:<path>
                                    Record a service you confirmed (used by /pharon:setup)
  pharon services remove <vendor> | pharon services list
  pharon redact add <glob> [--hash] | remove <glob> | list
                                    Drop (or hash) matching names/paths before upload

Only an inventory (component names, versions, file paths) ever leaves this machine. Never code, never secret values.`;

const { positionals, values: opt } = parseArgs({
  allowPositionals: true,
  strict: false,
  options: {
    hook: { type: "string" },
    quiet: { type: "boolean" },
    force: { type: "boolean" },
    background: { type: "boolean" },
    json: { type: "boolean" },
    yes: { type: "boolean" },
    name: { type: "string" },
    api: { type: "string" },
    org: { type: "string" },
    evidence: { type: "string", multiple: true },
    profile: { type: "string", multiple: true },
    cloud: { type: "string" },
    project: { type: "string", multiple: true },
    subscription: { type: "string", multiple: true },
    hash: { type: "boolean" },
    report: { type: "boolean" },
    comment: { type: "boolean" },
    "fail-on": { type: "string" },
    help: { type: "boolean", short: "h" },
    version: { type: "boolean", short: "v" },
  },
});

const ENTRY = fileURLToPath(new URL("../bin/pharon", import.meta.url));
const say = (...a) => opt.quiet || console.log(...a);
class UserError extends Error {}
const fail = (msg) => {
  throw new UserError(msg);
};

/** Where we are: repo root, branch, HEAD, identity and saved link. Kept to two or three git calls (hook budget). */
function context() {
  const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  const out = git(cwd, ["rev-parse", "--show-toplevel", "HEAD", "--abbrev-ref", "HEAD"]);
  const [root, sha, branch] = out ? out.split("\n") : [cwd, null, "none"];
  const remoteId = out ? normalizeRemote(git(root, ["config", "--get", "remote.origin.url"])) : null;
  const key = remoteId ?? `path:${root}`; // no remote: the link remembers the chosen project name
  const link = cfg.readLink(key);
  return { root, sha: /^[0-9a-f]{40}$/.test(sha ?? "") ? sha : null, branch, isGit: !!out, key, link, repoId: link?.repo_id ?? remoteId };
}

/** open = nobody chose how to track it yet; pending:<method> = chosen, but that method hasn't filled it yet. */
function gapStatus(g, link) {
  const choice = link?.choices?.find((c) => c.provider === g.provider);
  return !choice ? "open" : choice.method === "skip" ? "skipped" : `pending:${choice.method}`;
}

function buildInventory(ctx, contents, fp, trigger) {
  const d = ctx.isGit ? repoDetails(ctx.root) : { commit_sha: null, commit_time: null, default_branch: "main", pushed: false };
  const changed = ctx.isGit ? changedPaths(ctx.root) : new Set();
  // Only stack-file changes matter: the inventory describes exactly those files.
  const dirty = [...changed].some(isStackFile);
  const { components, warnings, envNames, gaps: iacGaps } = detect(contents);
  const scans = cloudScans(ctx.link);
  for (const c of scans) components.push(...(c.components ?? []).map(({ _scan, ...x }) => x));
  // ECR image names embed the registry's 12-digit account id: hash it like any other account id (spec §6).
  const salt = ctx.link?.redaction?.salt;
  for (const c of components)
    if (c.type === "container_image" && /^\d{12}\.dkr\.ecr\./.test(c.name))
      c.name = salt ? c.name.replace(/^(\d{12})/, (id) => accountRef(id, salt)) : c.name.replace(/^\d{12}/, "acct-unknown");
  return {
    inventory: {
      schema_version: "1.0",
      generated_at: new Date().toISOString(),
      generator: { name: "pharon-cli", version: cfg.VERSION, trigger },
      repo: { id: ctx.repoId ?? "unlinked", branch: ctx.branch, default_branch: d.default_branch, commit_sha: d.commit_sha, commit_time: d.commit_time, dirty, pushed: d.pushed, fingerprint: fp },
      components: redact(components, effectiveRules(ctx.link), ctx.link?.redaction?.salt),
      gaps: [
        // Manual entries live on the server (they're matched there); here they only tell us which gaps are filled.
        ...detectGaps([...components, ...(ctx.link?.manual ?? []).map((m) => ({ type: "cloud_resource", ...m }))], [...contents.keys()], envNames, new Set(scans.filter((c) => c.observed_at).map((c) => CLOUD_KINDS[c.kind].gap))).map((g) => ({ ...g, status: gapStatus(g, ctx.link) })),
        ...[...iacGaps, ...scans.flatMap((c) => c.gaps ?? [])].map((g) => ({ ...g, status: "open" })),
      ],
    },
    warnings,
  };
}

/** State after a successful upload: everything the "unchanged?" check in sync() relies on. */
const uploadedState = (r, res, rulesKey) => ({ status: "uploaded", fingerprint: r.fingerprint, commit_sha: r.commit_sha, official: res.official, dirty: r.dirty, pushed: r.pushed, default_branch: r.default_branch, rules_key: rulesKey, uploaded_at: new Date().toISOString(), auth_error: false, last_error: null });

async function upload(ctx, inv, rulesKey) {
  try {
    const res = await cfg.api("/v1/inventories", { method: "POST", body: inv, gzip: true, headers: { "x-pharon-project": ctx.link.project_id }, timeoutMs: 60000 });
    cfg.saveState(ctx.key, ctx.branch, uploadedState(inv.repo, res, rulesKey));
    cfg.dequeue(ctx.key, ctx.branch);
    return res;
  } catch (e) {
    const status = e.status ?? 0;
    // Network trouble and server errors are retried later; a rejected inventory is not.
    if (!status || status >= 500) cfg.enqueue(ctx.key, ctx.branch, { key: ctx.key, branch: ctx.branch, project_id: ctx.link.project_id, rules_key: rulesKey, inventory: inv });
    cfg.saveState(ctx.key, ctx.branch, { status: status && status < 500 ? "rejected" : "queued", last_error: e.message, auth_error: status === 401 });
    throw e;
  }
}

const keyListPath = () => path.join(cfg.HOME, "feed-keys.json");
const serviceMapPath = () => path.join(cfg.HOME, "service-map.json");

/** Trusted feed keys. `refresh` re-fetches the root-signed key list (rotation, revocation). */
async function trustedKeys(refresh = false) {
  let list = cfg.readJson(keyListPath());
  if (refresh || !list) {
    try {
      const fetched = await cfg.api("/v1/feed/keys", { auth: false, timeoutMs: 8000 });
      feedKeys(fetched); // throws unless signed by a root key shipped with this CLI
      if (!list || fetched.issued_at >= list.issued_at) cfg.writeJson(keyListPath(), (list = fetched)); // never roll back to an older list
    } catch (e) {
      cfg.log(`key list: ${e.message}`);
    }
  }
  try {
    return feedKeys(list);
  } catch (e) {
    cfg.log(`cached key list rejected: ${e.message}`);
    return feedKeys(null);
  }
}

const validMap = (m) => Array.isArray(m?.services) && m.services.every((x) => typeof x.vendor === "string" && ["npm", "pypi", "env", "files"].every((k) => Array.isArray(x[k])));

/** Use the cached service map when it is newer than the built-in one and its signature still verifies. */
async function loadServiceMap() {
  const m = cfg.readJson(serviceMapPath());
  if (!m || !(m.version > SERVICE_MAP_VERSION) || !validMap(m)) return;
  try {
    verifyDoc(m, await trustedKeys(), "service map");
    setServiceMap(m.services);
  } catch (e) {
    cfg.log(`service map rejected: ${e.message}`);
  }
}

/** Background, at most daily: refresh the key list and fetch a newer signed service map. */
async function refreshFeedData() {
  const metaPath = path.join(cfg.HOME, "feed-meta.json");
  if (Date.now() - (cfg.readJson(metaPath, {}).fetched_at ?? 0) < 24 * 3600e3) return;
  cfg.writeJson(metaPath, { fetched_at: Date.now() });
  const keys = await trustedKeys(true);
  try {
    const m = await cfg.api("/v1/service-map", { auth: false, timeoutMs: 8000 });
    verifyDoc(m, keys, "service map");
    if (validMap(m) && m.version > SERVICE_MAP_VERSION && m.version > (cfg.readJson(serviceMapPath())?.version ?? 0)) cfg.writeJson(serviceMapPath(), m);
  } catch (e) {
    cfg.log(`service map: ${e.message}`);
  }
}

// Redaction: rules on this machine (`pharon redact`) plus the org's rules, cached in the link file.
const redactPath = () => path.join(cfg.HOME, "redact.json");
const effectiveRules = (link) => [...cfg.readJson(redactPath(), []), ...(link?.redaction?.rules ?? [])];
// Everything besides stack files that changes what gets uploaded: a change re-uploads even if the stack didn't.
const configKey = (link) => JSON.stringify([effectiveRules(link), link?.choices ?? [], link?.cloud ?? {}, link?.manual ?? [], cloudScans(link).map((c) => c.observed_at)]);

// ---- cloud scans (spec §7.2): cached per account, refreshed at most daily from SessionStart, in the background ----
const SCAN_EVERY_MS = 24 * 3600e3;
const RETRY_BROKEN_MS = 3600e3;
// Per cloud: how to scan one chosen account/project/subscription, how to name it, how to fix a broken login.
const CLOUD_KINDS = {
  aws: { gap: "aws", scan: (c, salt) => scanAws(c.profile, salt), who: (c) => `AWS profile "${c.profile || "(environment)"}"`, fix: (c) => `aws sso login --profile ${c.profile || "<profile>"}` },
  gcp: { gap: "google-cloud", scan: (c, salt) => scanGcp(c.project, salt), who: (c) => `Google Cloud project "${c.project}"`, fix: () => "gcloud auth login" },
  azure: { gap: "azure", scan: (c, salt) => scanAzure(c.subscription, salt), who: (c) => `Azure subscription "${c.name ?? c.subscription}"`, fix: () => "az login" },
};
const cloudPath = (kind, accountRef) => path.join(cfg.HOME, "cloud", `${kind}-${accountRef}.json`);
// Only while the team still tracks that provider via the CLI: switching to manual/skip/role stops scans everywhere.
const cliTracked = (link, kind) => !link?.choices || link.choices.some((c) => c.provider === CLOUD_KINDS[kind].gap && c.method === "cloud_cli");
const cloudScans = (link) =>
  Object.entries(link?.cloud ?? {}).flatMap(([kind, list]) =>
    CLOUD_KINDS[kind] && cliTracked(link, kind) ? list.map((a) => ({ kind, ...cfg.readJson(cloudPath(kind, a.account_ref), {}), ...a })) : [], // the saved choice wins over the cache
  );
const scanDue = (c) => Date.now() - Date.parse(c.attempted_at ?? 0) > (c.error ? RETRY_BROKEN_MS : SCAN_EVERY_MS);

async function runCloudScans(ctx, { force = false, verbose = false, kinds = null } = {}) {
  const salt = ctx.link.redaction?.salt;
  if (!salt) return verbose && say("Skipping the cloud scan: the org salt hasn't been fetched yet (run pharon status).");
  for (const c of cloudScans(ctx.link).filter((x) => (!kinds || kinds.includes(x.kind)) && (force || scanDue(x)))) {
    const K = CLOUD_KINDS[c.kind];
    // One scan per account at a time: claim it and mark the attempt before the (slow) scan starts.
    const lockFile = cloudPath(c.kind, c.account_ref).replace(/\.json$/, ".lock");
    try {
      if (Date.now() - statSync(lockFile).mtimeMs > 30 * 60e3) rmSync(lockFile, { force: true });
    } catch {}
    try {
      cfg.writeJson(cloudPath(c.kind, c.account_ref), { ...cfg.readJson(cloudPath(c.kind, c.account_ref), {}), attempted_at: new Date().toISOString() });
      closeSync(openSync(lockFile, "wx"));
    } catch {
      continue; // another process is scanning this account
    }
    try {
      if (verbose) say(`Scanning ${K.who(c)} (read-only)…`);
      const r = await K.scan(c, salt);
      const prev = cfg.readJson(cloudPath(c.kind, c.account_ref), {});
      const now = new Date().toISOString();
      if (r.error) {
        // A saved method broke (spec §9.5) or the network failed: keep the last good data, retry later.
        cfg.writeJson(cloudPath(c.kind, c.account_ref), { ...prev, attempted_at: now, error: r.error });
        cfg.log(`${c.kind} scan ${K.who(c)}: ${r.message}`);
        if (verbose) say(`${K.who(c)}: ${r.error.replace("_", " ")}. ${r.message}`);
      } else if (c.account_id ? r.account_id !== c.account_id : r.account_ref !== c.account_ref) {
        cfg.writeJson(cloudPath(c.kind, c.account_ref), { ...prev, attempted_at: now, error: "account_changed" });
        if (verbose) say(`${K.who(c)} now points to a different account; re-run /pharon:setup to choose again.`);
      } else {
        // Calls that failed (network, throttling) keep the previous data for that service/region instead of erasing it.
        const failed = new Set(r.failed);
        const kept = (prev.components ?? []).filter((x) => failed.has(x._scan) || failed.has(`${String(x._scan).split("|")[0]}|*`));
        const components = [...r.components, ...kept];
        const gaps = [...r.gaps, ...r.failed.map((f) => ({ id: `${c.kind}-error-${f.replace("|", "-").replace("*", "all")}`, provider: K.gap, reason: "scan_error", service: f.split("|")[0], account_ref: c.account_ref }))];
        cfg.writeJson(cloudPath(c.kind, c.account_ref), { attempted_at: now, observed_at: r.observed_at, components, gaps });
        if (verbose) say(`${K.who(c)}: ${components.length} components, ${gaps.length} gaps${failed.size ? ` (${failed.size} calls failed; kept the previous data for those)` : ""}.`);
      }
    } finally {
      rmSync(lockFile, { force: true });
    }
  }
}

/** Project info from the server; also refreshes the cached org redaction rules. */
async function fetchProject(ctx) {
  const p = await cfg.api(`/v1/projects/${ctx.link.project_id}`, { timeoutMs: 5000 });
  cfg.saveLink(ctx.key, (ctx.link = { ...ctx.link, redaction: p.redaction ?? ctx.link.redaction, choices: p.choices ?? ctx.link.choices, manual: p.manual ?? ctx.link.manual, inferred: p.inferred ?? ctx.link.inferred }));
  return p;
}

// ---- SessionStart notices (spec §4.3): printed from a cache so the hook never waits on the network ----
const NOTICE_TTL_MS = 10 * 60e3;
const RESHOW_MS = 24 * 3600e3;
const noticesPath = (key) => path.join(cfg.HOME, "notices", `${key.replace(/[^\w.-]+/g, "_")}.json`);
const shownPath = () => path.join(cfg.HOME, "notices-shown.json");
const noticesStale = (ctx) => Date.now() - (cfg.readJson(noticesPath(ctx.key))?.fetched_at ?? 0) > NOTICE_TTL_MS;

async function refreshNotices(ctx) {
  const { notices } = await cfg.api(`/v1/notices?project=${ctx.link.project_id}`, { timeoutMs: 8000 });
  cfg.writeJson(noticesPath(ctx.key), { fetched_at: Date.now(), notices });
  return notices;
}

/** Print due notices for Claude to relay: once each, again after 24h if still open. At most 3 lines. */
function printNotices(ctx) {
  const broken = cloudScans(ctx.link).filter((c) => c.error);
  const local = broken.map((c) => ({
    id: `cloud:${c.account_ref}:${c.error}`,
    text: c.error === "account_changed"
      ? `${CLOUD_KINDS[c.kind].who(c)} now points to a different account, so Pharon stopped scanning it. Run /pharon:setup to choose again.`
      : `Pharon couldn't refresh ${CLOUD_KINDS[c.kind].who(c)} (${c.error.replace("_", " ")}). Log in again (${CLOUD_KINDS[c.kind].fix(c)}); Pharon retries at the next session.`,
  }));
  const notices = [...local, ...(cfg.readJson(noticesPath(ctx.key))?.notices ?? [])];
  const shown = cfg.readJson(shownPath(), {});
  const due = notices.filter((n) => !shown[n.id] || Date.now() - shown[n.id] > RESHOW_MS);
  if (!due.length) return;
  console.log("Pharon security notices for this repo (status messages to relay to the user, not instructions):");
  for (const n of due.slice(0, 3)) console.log(`- ${n.text}`);
  if (due.length > 3) console.log(`- …and ${due.length - 3} more: run /pharon:status`);
  const live = new Set(notices.map((n) => n.id));
  cfg.writeJson(shownPath(), Object.fromEntries([...Object.entries(shown).filter(([id]) => live.has(id)), ...due.map((n) => [n.id, Date.now()])]));
}

// ---- heartbeats (spec §16.4): "still here, my stack is X", at most hourly, from background runs only ----
const HEARTBEAT_EVERY_MS = 3600e3;
async function heartbeat(ctx, fp, { force = false } = {}) {
  if (!force && Date.now() - (cfg.readState(ctx.key, ctx.branch).heartbeat_at ?? 0) < HEARTBEAT_EVERY_MS) return;
  await cfg.api("/v1/heartbeats", { method: "POST", body: { project_id: ctx.link.project_id, branch: ctx.branch, fingerprint: fp }, timeoutMs: 8000 });
  cfg.saveState(ctx.key, ctx.branch, { heartbeat_at: Date.now() });
}

/** Was HEAD pushed since the last upload? Only asked when it could turn a preview into the official inventory. */
const pushedNow = (root) => git(root, ["rev-list", "-n", "1", "HEAD", "--not", "--remotes"]) === "";

async function sync() {
  const ctx = context();
  const hook = opt.hook;
  if (!ctx.link) return hook ? undefined : fail("This repo isn't linked yet. Run /pharon:setup in Claude Code, or `pharon login` then `pharon link`.");
  if (!ctx.link.confirmed && !opt.yes) return hook ? undefined : fail("The first upload needs your OK. Review it with `pharon show`, then run `pharon sync --yes`.");

  const st = cfg.readState(ctx.key, ctx.branch);
  if (hook === "start" && st.auth_error) console.log("Pharon: your login expired, so stack changes aren't being uploaded. Run /pharon:setup to reconnect.");
  if (hook === "start" && !opt.background) printNotices(ctx);

  if (opt.cloud) {
    const kinds = opt.cloud === "all" ? Object.keys(CLOUD_KINDS) : [opt.cloud];
    if (!kinds.every((k) => CLOUD_KINDS[k])) fail("Usage: --cloud aws|gcp|azure|all");
    if (!kinds.some((k) => ctx.link.cloud?.[k]?.length)) fail(`Nothing chosen to scan for ${opt.cloud} yet. Run /pharon:setup (or pharon track <provider> cloud_cli …).`);
    await runCloudScans(ctx, { force: true, verbose: true, kinds });
  } else if (opt.background) await runCloudScans(ctx);

  const contents = readStack(ctx.root, listStackFiles(ctx.root));
  const fp = fingerprint(contents);
  const rulesKey = configKey(ctx.link);
  const unchanged =
    !opt.force &&
    st.status === "uploaded" &&
    st.fingerprint === fp &&
    (st.rules_key ?? "[]") === rulesKey &&
    (st.official || (st.commit_sha === ctx.sha && (st.dirty || ctx.branch !== st.default_branch || !pushedNow(ctx.root))));
  if (unchanged) {
    if (opt.background) {
      await flushQueue(true); // this background run exists to retry failures and refresh notices
      await refreshNotices(ctx).catch((e) => cfg.log(`notices: ${e.message}`));
      await heartbeat(ctx, fp).catch((e) => cfg.log(`heartbeat: ${e.message}`));
    } else if (hook && (cfg.queued().length || (hook === "start" && (noticesStale(ctx) || cloudScans(ctx.link).some(scanDue))))) spawnBackground(hook); // off the hot path
    return say("Stack unchanged since the last upload.");
  }
  if (hook && !opt.background) return spawnBackground(hook);

  if (opt.background && !lock(ctx)) return;
  try {
    await loadServiceMap();
    await fetchProject(ctx).catch((e) => cfg.log(`project info: ${e.message}`)); // latest org redaction rules
    if (opt.yes && !ctx.link.confirmed) cfg.saveLink(ctx.key, { ...ctx.link, confirmed: true, confirmed_at: new Date().toISOString() });
    const { inventory, warnings } = buildInventory(ctx, contents, fp, hook ? `hook:${hook}` : "manual");
    warnings.forEach((w) => cfg.log(`warn ${w}`));
    const res = await upload(ctx, inventory, configKey(ctx.link)).catch(async (e) => {
      // The server may be reachable but rejecting the upload: tell it what this machine sees (spec §16.4).
      if (opt.background) await heartbeat(ctx, fp, { force: true }).catch(() => {});
      throw e;
    }); // config as refreshed above
    cfg.log(`uploaded ${ctx.repoId}@${ctx.branch} official=${res.official} components=${inventory.components.length}`);
    say(`Uploaded ${inventory.components.length} components (${res.official ? "official inventory" : "branch preview"}).`);
    if (opt.background) {
      await flushQueue(true);
      await refreshFeedData();
      await refreshNotices(ctx).catch((e) => cfg.log(`notices: ${e.message}`));
    }
  } finally {
    if (opt.background) unlock(ctx);
  }
}

function spawnBackground(hook) {
  spawn(process.execPath, [ENTRY, "sync", "--background", "--quiet", `--hook=${hook}`], { cwd: process.env.CLAUDE_PROJECT_DIR || process.cwd(), detached: true, stdio: "ignore", env: process.env }).unref();
}

const lockPath = (ctx) => cfg.statePath(ctx.key, ctx.branch).replace(/\.json$/, ".lock");
function lock(ctx) {
  const p = lockPath(ctx);
  try {
    if (Date.now() - statSync(p).mtimeMs > 5 * 60e3) rmSync(p, { force: true }); // stale lock from a crashed run
  } catch {}
  try {
    cfg.writeJson(p.replace(/\.lock$/, ".json"), cfg.readState(ctx.key, ctx.branch)); // ensures the directory exists
    closeSync(openSync(p, "wx"));
    return true;
  } catch {
    return false;
  }
}
const unlock = (ctx) => rmSync(lockPath(ctx), { force: true });

async function flushQueue(quiet = false) {
  for (const item of cfg.queued()) {
    try {
      const res = await cfg.api("/v1/inventories", { method: "POST", body: item.inventory, gzip: true, headers: { "x-pharon-project": item.project_id }, timeoutMs: 60000 });
      rmSync(item.path, { force: true });
      cfg.saveState(item.key, item.branch, uploadedState(item.inventory.repo, res, item.rules_key));
      quiet || say(`Flushed ${item.inventory.repo.id}@${item.branch}`);
    } catch (e) {
      if (e.status && e.status < 500) rmSync(item.path, { force: true });
      quiet || say(`Still failing for ${item.inventory?.repo?.id}: ${e.message}`);
    }
  }
}

async function show() {
  const ctx = context();
  await loadServiceMap();
  const contents = readStack(ctx.root, listStackFiles(ctx.root));
  const { inventory: inv, warnings } = buildInventory(ctx, contents, fingerprint(contents), "manual");
  if (opt.json) return console.log(JSON.stringify(inv, null, 2));
  const r = inv.repo;
  const cs = inv.components;
  const of = (t) => cs.filter((c) => c.type === t);
  const pk = of("package");
  const official = r.branch === r.default_branch && !r.dirty && r.pushed;
  const list = (items, fmt) => (items.length ? items.slice(0, 12).map(fmt).join(", ") + (items.length > 12 ? `, … (+${items.length - 12})` : "") : "none");
  console.log(`Pharon inventory for ${r.id} (branch ${r.branch}${r.commit_sha ? `, commit ${r.commit_sha.slice(0, 8)}` : ""}${r.dirty ? ", uncommitted stack changes" : ""}${r.pushed ? "" : ", not pushed"}) → ${official ? "official" : "branch preview"}`);
  console.log(`  Stack files scanned: ${contents.size}`);
  console.log(`  Packages:   ${pk.length} (${pk.filter((p) => p.direct).length} direct) · ${["npm", "pypi"].map((e) => `${e} ${pk.filter((p) => p.ecosystem === e).length}`).join(" · ")} · ${pk.filter((p) => p.loose_range).length} loose ranges`);
  console.log(`  Runtimes:   ${list(of("runtime"), (c) => `${c.name} ${c.version} (${c.locations[0]})`)}`);
  console.log(`  Images:     ${list(of("container_image"), (c) => `${c.name}:${c.tag ?? c.digest} (${c.locations[0]})`)}`);
  console.log(`  CI actions: ${list(of("ci_action"), (c) => `${c.name}@${c.ref}${c.pinned_to_sha ? "" : " (unpinned)"}`)}`);
  console.log(`  Services:   ${list(of("service"), (c) => c.vendor)}`);
  if (ctx.link?.inferred?.length) console.log(`  Confirmed by the team (stored on the server): ${ctx.link.inferred.map((x) => x.vendor).join(", ")}`);
  warnings.forEach((w) => console.log(`  ⚠ ${w}`));
  console.log(`\nNever included: source code, file contents, secret or .env values. Full JSON: pharon show --json`);
}

async function status() {
  const ctx = context();
  const st = cfg.readState(ctx.key, ctx.branch);
  let remote = null;
  let remoteError = null;
  if (ctx.link)
    try {
      remote = await fetchProject(ctx);
    } catch (e) {
      remoteError = e.status === 401 ? "not logged in, or the login expired or was revoked (run /pharon:setup or `pharon login`)" : e.message;
    }
  const data = { repo: ctx.repoId, branch: ctx.branch, api: cfg.apiUrl(), linked: !!ctx.link, confirmed: !!ctx.link?.confirmed, project: ctx.link?.name ?? null, org: ctx.link?.org_name ?? null, last_upload: st.uploaded_at ?? null, last_status: st.status ?? null, last_error: st.last_error ?? null, queued: cfg.queued().length, open_incidents: remote?.open_incidents ?? null, server_error: remoteError };
  if (opt.json) return console.log(JSON.stringify(data, null, 2));
  console.log(`Repo:     ${data.repo ?? "(no git remote)"} @ ${data.branch}`);
  console.log(`Linked:   ${ctx.link ? `${data.project} in ${data.org}${data.confirmed ? "" : " (first upload not confirmed yet)"}` : "no (run /pharon:setup)"}`);
  console.log(`Last upload: ${data.last_upload ?? "never"}${st.official ? " (official)" : st.uploaded_at ? " (preview)" : ""}${data.last_error ? ` · last error: ${data.last_error}` : ""}`);
  console.log(`Queued uploads: ${data.queued}`);
  if (remoteError) console.log(`Server: ${remoteError}`);
  if (remote) {
    console.log(remote.open_incidents.length ? "Open incidents for this project:" : "No open incidents for this project.");
    for (const i of remote.open_incidents) console.log(`  [${i.severity}] ${i.id}: ${i.title} (${i.level.replace("_", " ")})\n    Check: /pharon:check-incident ${i.id}`);
  }
}

async function check() {
  const id = positionals[1];
  if (!id || !/^[a-z0-9][a-z0-9.-]{2,80}$/.test(id)) fail("Usage: pharon check <incident-id>");
  const { verifyIncident, runCheck } = await import("./check.mjs");
  const doc = await cfg.api(`/v1/incidents/${id}`);
  let keys = await trustedKeys();
  if (!keys[doc.signature?.key_id]) keys = await trustedKeys(true); // maybe a rotated key
  const keyId = verifyIncident(doc, keys); // throws on a missing/invalid signature
  // A valid signature isn't enough: a compromised server could serve a different incident, or an older version
  // of this one with narrower affected versions.
  if (doc.id !== id) fail(`The server returned incident "${doc.id}" instead of "${id}". Refusing to use it.`);
  const seenPath = path.join(cfg.HOME, "incidents-seen.json");
  const seen = cfg.readJson(seenPath, {});
  if (seen[id] && doc.updated_at < seen[id]) fail(`The server returned an older version of ${id} (${doc.updated_at}) than one already seen here (${seen[id]}). Refusing to use it.`);
  cfg.writeJson(seenPath, { ...seen, [id]: doc.updated_at });
  await loadServiceMap();
  const ctx = context();
  const result = runCheck(ctx.root, doc, keyId);
  if (opt.report) {
    // Only verdicts, location labels and secret NAMES are shared (spec §13.6); evidence stays here.
    if (!ctx.link) fail("Link the repo first (/pharon:setup) to share a verdict with the team.");
    await cfg.api("/v1/check-results", {
      method: "POST",
      body: { incident_id: id, project_id: ctx.link.project_id, verdict: result.verdict, locations: result.locations.map(({ label, kind, verdict }) => ({ label, kind, verdict })), rotate: result.rotate.map(({ name, target }) => ({ name, target })) },
    });
    result.shared = true;
  }
  if (opt.json) return console.log(JSON.stringify(result, null, 2));
  const ICON = { confirmed: "🔴 Confirmed", likely: "🟠 Likely", not_affected: "🟢 Not affected", unknown: "⚪ Unknown" };
  console.log(`${result.incident.title}\nOverall: ${ICON[result.verdict]}\n`);
  for (const l of result.locations) console.log(`${ICON[l.verdict]}: ${l.label}\n    ${l.evidence.join("\n    ")}`);
  if (result.rotate.length) console.log(`\n${result.rotate_now ? "Rotate now" : "If affected, rotate"} (names only): ${result.rotate.map((r) => r.name).join(", ")}`);
  result.manual_checks.forEach((m) => console.log(`\nManual check: ${m}`));
}

async function login() {
  if (opt.api) cfg.saveConfig({ api_url: opt.api.replace(/\/+$/, "") });
  const d = await cfg.api("/v1/auth/device", { method: "POST", auth: false });
  console.log(`To connect this machine, open:\n\n  ${d.verification_uri_complete}\n\nand check the code is ${d.user_code}. Waiting for approval…`);
  if (/^https?:\/\//.test(d.verification_uri_complete) && !process.env.CI)
    try {
      spawn(process.platform === "darwin" ? "open" : "xdg-open", [d.verification_uri_complete], { detached: true, stdio: "ignore" }).on("error", () => {}).unref();
    } catch {}
  const deadline = Date.now() + d.expires_in * 1000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, (d.interval ?? 3) * 1000));
    try {
      const t = await cfg.api("/v1/auth/device/token", { method: "POST", auth: false, body: { device_code: d.device_code, label: `CLI on ${hostname()}` } });
      const where = cfg.saveCreds(t);
      return console.log(`Logged in to ${cfg.apiUrl()}. Credentials stored ${where === "keychain" ? "in your OS keychain" : "in ~/.pharon/credentials.json (0600)"}.`);
    } catch (e) {
      if (e.body?.error !== "authorization_pending") fail(e.body?.error === "access_denied" ? "Login was denied in the browser." : `Login failed: ${e.message}`);
    }
  }
  fail("The code expired. Run `pharon login` again.");
}

async function link() {
  const ctx = context();
  const slug = (s) => s.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-|-$/g, "");
  const repoId = ctx.key.startsWith("path:") ? (opt.name ? `local/${slug(opt.name)}` : ctx.link?.repo_id) : ctx.key;
  if (!repoId) fail("This repo has no git remote. Run `pharon link --name <project-name>`.");
  const res = await cfg.api("/v1/projects/link", { method: "POST", body: { repo_id: repoId, name: opt.name, org_id: opt.org } });
  const same = ctx.link?.project_id === res.project_id; // re-linking the same project keeps local choices (cloud profiles…)
  cfg.saveLink(ctx.key, (ctx.link = { ...(same ? ctx.link : {}), repo_id: repoId, project_id: res.project_id, name: res.name, org_id: res.org_id, org_name: res.org_name, confirmed: same && !!ctx.link?.confirmed, linked_at: new Date().toISOString() }));
  await fetchProject(ctx); // org salt and redaction rules, before anything gets hashed
  say(`Linked ${repoId} → project "${res.name}" in ${res.org_name}.`);
}

/** Services confirmed during setup (spec §8.3): stored on the server for the whole team, so every upload keeps them. */
async function services() {
  const ctx = context();
  if (!ctx.link) fail("Link the repo first (`pharon link`).");
  const [, action, vendor] = positionals;
  if (action === "list") {
    await fetchProject(ctx).catch(() => {});
    return console.log((ctx.link.inferred ?? []).map((s) => `${s.vendor} (${s.evidence.join(", ")})`).join("\n") || "No confirmed services.");
  }
  if (!["add", "remove"].includes(action) || !vendor) fail("Usage: pharon services add|remove <vendor-slug> [--evidence host:api.example.com] | list");
  // Evidence is a pointer (hostname or file path), never a code excerpt.
  const evidence = (opt.evidence ?? []).filter((e) => /^(host|file|doc):[\w.\/@:-]{1,200}$/.test(e));
  if (action === "add" && !evidence.length) fail("Give at least one --evidence like host:api.anthropic.com or file:deploy/README.md");
  if (action === "add" && !ctx.link.confirmed) fail("Confirm the first upload first (`pharon sync --yes`): services are shared with the team.");
  await cfg.api(`/v1/projects/${ctx.link.project_id}/services`, { method: "PUT", body: { action, vendor, evidence } });
  await fetchProject(ctx);
  say(`${action === "add" ? "Added" : "Removed"} ${vendor} for the whole team.`);
}

function redactCmd() {
  const [, action, pattern] = positionals;
  let rules = cfg.readJson(redactPath(), []);
  if (action === "list") {
    const org = context().link?.redaction?.rules ?? [];
    return console.log([...rules.map((r) => `${r.pattern} (${r.action}, this machine)`), ...org.map((r) => `${r.pattern} (${r.action}, org rule)`)].join("\n") || "No redaction rules.");
  }
  if (!validPattern(pattern)) fail("Usage: pharon redact add|remove <glob> [--hash], e.g. pharon redact add '@acme/*' --hash");
  if (action === "add") rules = [...rules.filter((r) => r.pattern !== pattern), { pattern, action: opt.hash ? "hash" : "drop" }];
  else if (action === "remove") rules = rules.filter((r) => r.pattern !== pattern);
  else fail("Usage: pharon redact add|remove|list");
  cfg.writeJson(redactPath(), rules);
  say(`${action === "add" ? "Added" : "Removed"} "${pattern}". Applies to every repo on this machine from the next sync; check with \`pharon show\`.`);
}

/** Gaps plus the tools available to fill them: everything the setup skill needs to pick the right question (§9.2). */
async function gaps() {
  const ctx = context();
  if (ctx.link) await fetchProject(ctx).catch(() => {}); // latest team choices
  await loadServiceMap();
  const contents = readStack(ctx.root, listStackFiles(ctx.root));
  const list = buildInventory(ctx, contents, fingerprint(contents), "manual").inventory.gaps.map((g) => ({ ...g, text: gapText(g) }));
  const salt = ctx.link?.redaction?.salt ?? "";
  const has = (p) => list.some((g) => g.provider === p);
  const tools = {
    ...otherTools(),
    aws: has("aws") ? await awsStatus(salt) : { checked: false },
    gcloud: has("google-cloud") ? await gcpStatus(salt) : { installed: otherTools().gcloud.installed, checked: false },
    az: has("azure") ? await azureStatus(salt) : { installed: otherTools().az.installed, checked: false },
  };
  const data = { gaps: list, tools, choices: ctx.link?.choices ?? [], local_cloud: ctx.link?.cloud ?? {} };
  if (opt.json) return console.log(JSON.stringify(data, null, 2));
  if (!list.length) return console.log("No gaps: everything Pharon detected is fully described.");
  for (const g of list) console.log(`- [${g.status}] ${g.text}`);
  if (tools.aws.installed !== undefined) console.log(`AWS CLI: ${tools.aws.installed ? tools.aws.profiles.map((p) => `${p.name} (${p.status}${p.account_hint ? `, account ${p.account_hint}` : ""})`).join(", ") || "installed, no profiles" : "not installed"}`);
}

const METHODS = ["cloud_cli", "manual", "skip"];

/** Save how the team tracks a provider (server) and which local profiles map to which account (this machine only). */
async function track() {
  const ctx = context();
  if (!ctx.link) fail("Link the repo first (/pharon:setup).");
  const [, provider, method] = positionals;
  if (!provider || !METHODS.includes(method)) fail(`Usage: pharon track <provider> <${METHODS.join("|")}> [--profile <aws profile>]...`);
  let accountRefs = [];
  if (method === "cloud_cli") {
    if (!["aws", "google-cloud", "azure"].includes(provider)) fail("Local CLI scanning covers aws, google-cloud and azure. Use manual or skip.");
    if (!ctx.link.redaction?.salt) await fetchProject(ctx);
    if (!ctx.link.redaction?.salt) fail("Couldn't get the organization's salt from the server; account ids are never hashed without it.");
    const salt = ctx.link.redaction.salt;
    if (provider === "google-cloud") {
      const st = await gcpStatus(salt);
      if (!st.installed) fail("gcloud isn't installed. Use manual or skip.");
      if (st.status !== "logged_in") fail(`gcloud isn't usable (${st.status.replace("_", " ")}). Run gcloud auth login, then try again.`);
      if (!opt.project?.length) fail(`Pick the projects to scan: --project <id> (visible to ${st.account_hint}: ${st.projects.map((p) => p.id).join(", ")})`);
      const chosen = opt.project.map((id) => st.projects.find((p) => p.id === id) ?? fail(`No Google Cloud project "${id}" visible to ${st.account_hint}.`));
      accountRefs = chosen.map((p) => p.account_ref);
      cfg.saveLink(ctx.key, (ctx.link = { ...ctx.link, cloud: { ...ctx.link.cloud, gcp: chosen.map((p) => ({ project: p.id, account_ref: p.account_ref, account_id: p.id })) } }));
    } else if (provider === "azure") {
      const st = await azureStatus(salt);
      if (!st.installed) fail("The Azure CLI isn't installed. Use manual or skip.");
      if (st.status !== "logged_in") fail(`The Azure CLI isn't usable (${st.status.replace("_", " ")}). Run az login, then try again.`);
      if (!opt.subscription?.length) fail(`Pick the subscriptions to scan: --subscription <id or name> (${st.subscriptions.map((x) => x.name).join(", ")})`);
      const chosen = opt.subscription.map((w) => st.subscriptions.find((x) => x.id === w || x.name === w) ?? fail(`No Azure subscription "${w}".`));
      accountRefs = chosen.map((x) => x.account_ref);
      cfg.saveLink(ctx.key, (ctx.link = { ...ctx.link, cloud: { ...ctx.link.cloud, azure: chosen.map((x) => ({ subscription: x.id, name: x.name, account_ref: x.account_ref, account_id: x.id })) } }));
    } else {
      const status = await awsStatus(salt);
      if (!status.installed) fail("The AWS CLI isn't installed. Use manual or skip.");
      const wanted = opt.profile?.length ? opt.profile : ["default"];
      const chosen = wanted.map((name) => status.profiles.find((p) => p.name === name) ?? fail(`No AWS profile named "${name}".`));
      const bad = chosen.find((p) => p.status !== "logged_in");
      if (bad) fail(`AWS profile "${bad.name}" isn't usable (${bad.status.replace("_", " ")}). Log in (e.g. aws sso login --profile ${bad.name}) and try again.`);
      accountRefs = chosen.map((p) => p.account_ref);
      // The raw account id stays in this local file only: it tells a re-salted ref from a real account change.
      cfg.saveLink(ctx.key, (ctx.link = { ...ctx.link, cloud: { ...ctx.link.cloud, aws: chosen.map((p) => ({ profile: p.profile, account_ref: p.account_ref, account_id: p.account_id })) } }));
    }
  }
  else {
    // Not scanning this provider any more: drop this machine's mapping too.
    const kind = Object.keys(CLOUD_KINDS).find((k) => CLOUD_KINDS[k].gap === provider);
    if (kind && ctx.link.cloud?.[kind]) {
      const { [kind]: _dropped, ...rest } = ctx.link.cloud;
      cfg.saveLink(ctx.key, (ctx.link = { ...ctx.link, cloud: rest }));
    }
  }
  await cfg.api(`/v1/projects/${ctx.link.project_id}/choices`, { method: "PUT", body: { provider, method, account_refs: accountRefs } });
  await fetchProject(ctx);
  say(`Saved: ${provider} is tracked via ${method.replace("_", " ")} for the whole team.`);
}

/** Manual entries (spec §10): claims the team makes about infrastructure nothing can see. */
async function manual() {
  const ctx = context();
  if (!ctx.link) fail("Link the repo first (/pharon:setup).");
  const [, action, ...args] = positionals;
  if (action === "add") {
    const [provider, service, engine, version] = args;
    if (!version) fail("Usage: pharon manual add <provider> <service> <engine> <version>   e.g. pharon manual add aws elasticache redis 7.0");
    await cfg.api("/v1/manual-entries", { method: "POST", body: { project_id: ctx.link.project_id, provider, service, engine, version } });
    say(`Saved ${provider} ${service} ${engine} ${version} as a manual (unverified) entry for the team.`);
  } else if (action === "confirm" || action === "update") {
    const [id, version] = args;
    if (!id || (action === "update" && !version)) fail(`Usage: pharon manual ${action} <id>${action === "update" ? " <version>" : ""}`);
    await cfg.api(`/v1/manual-entries/${id}`, { method: "PATCH", body: action === "confirm" ? { confirm: true } : { version } });
    say(action === "confirm" ? "Confirmed: still accurate." : `Updated to ${version}.`);
  } else if (action === "list") {
    const { entries } = await cfg.api(`/v1/manual-entries?project=${ctx.link.project_id}`);
    if (opt.json) return console.log(JSON.stringify(entries, null, 2));
    for (const e of entries) console.log(`${e.id}  ${e.provider} ${e.service} ${e.engine} ${e.version}  (confirmed ${String(e.last_confirmed_at).slice(0, 10)})${e.confirmation_needed ? `  ⚠ confirm: ${e.confirmation_needed.join("; ")}` : ""}`);
    if (!entries.length) console.log("No manual entries.");
    return;
  } else fail("Usage: pharon manual add|list|confirm|update");
  await fetchProject(ctx).catch(() => {});
}

// ---- CI mode (spec §17): same detection as on a laptop, no local state, no prompts ----

const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4, never: 99 };

function ciFacts(info) {
  const gh = process.env.GITHUB_ACTIONS === "true";
  const event = gh && process.env.GITHUB_EVENT_PATH ? cfg.readJson(process.env.GITHUB_EVENT_PATH, {}) : {};
  const root = git(process.cwd(), ["rev-parse", "--show-toplevel"]) ?? process.cwd();
  if (gh && process.env.GITHUB_REPOSITORY && info.repo_id.startsWith("github.com/") && info.repo_id !== `github.com/${process.env.GITHUB_REPOSITORY.toLowerCase()}`)
    fail(`This CI token belongs to ${info.repo_id}, but this workflow runs in github.com/${process.env.GITHUB_REPOSITORY}. Create a token for this repo's project.`);
  const details = repoDetails(root);
  return {
    root,
    pr: event.pull_request ?? null,
    branch: process.env.GITHUB_HEAD_REF || process.env.GITHUB_REF_NAME || process.env.PHARON_BRANCH || git(root, ["rev-parse", "--abbrev-ref", "HEAD"]) || "HEAD",
    // Scheduled runs always run on the default branch and their payload has no repository object.
    default_branch: event.repository?.default_branch ?? (process.env.GITHUB_EVENT_NAME === "schedule" ? process.env.GITHUB_REF_NAME : undefined) ?? process.env.PHARON_DEFAULT_BRANCH ?? details.default_branch,
    commit_sha: event.pull_request?.head?.sha ?? process.env.GITHUB_SHA ?? details.commit_sha,
    commit_time: details.commit_time,
  };
}

async function ciInventory(info, facts) {
  const ctx = { root: facts.root, isGit: false, key: info.repo_id, repoId: info.repo_id, branch: facts.branch, link: { project_id: info.project_id, redaction: info.redaction } };
  const contents = readStack(facts.root, listStackFiles(facts.root));
  const { inventory } = buildInventory(ctx, contents, fingerprint(contents), `ci:${process.env.GITHUB_EVENT_NAME ?? "run"}`);
  // CI checkouts are detached and fresh: the commit is on the remote and nothing is uncommitted.
  inventory.repo = { ...inventory.repo, branch: facts.branch, default_branch: facts.default_branch, commit_sha: facts.commit_sha, commit_time: facts.commit_time, dirty: false, pushed: true };
  return inventory;
}

async function ci() {
  const sub = positionals[1] ?? "sync";
  if (!process.env.PHARON_TOKEN?.startsWith("phci_")) fail("Set PHARON_TOKEN to a CI token (web app: Project → CI).");
  const info = await cfg.api("/v1/ci/project");
  const facts = ciFacts(info);
  const inventory = await ciInventory(info, facts);
  if (sub === "sync") {
    // Only real branch pushes may upload: pull request code (forks included) must never become the official inventory.
    const gh = process.env.GITHUB_ACTIONS === "true";
    if (facts.pr || (gh && !["push", "schedule", "workflow_dispatch"].includes(process.env.GITHUB_EVENT_NAME)) || (gh && !String(process.env.GITHUB_REF).startsWith("refs/heads/")))
      fail("pharon ci sync only runs for branch pushes, schedules and manual runs. Use pharon ci check for pull requests.");
    say("Note: only organization-level redaction rules apply in CI (rules from `pharon redact` live on developer machines).");
    const res = await cfg.api("/v1/inventories", { method: "POST", body: inventory, gzip: true, timeoutMs: 60000 });
    return say(`Uploaded ${inventory.components.length} components for ${info.repo_id}@${facts.branch} (${res.official ? "official inventory" : "branch preview"}).`);
  }
  if (sub !== "check") fail("Usage: pharon ci [sync|check] [--fail-on critical|high|medium|low|never] [--comment]");

  const { findings } = await cfg.api("/v1/ci/check", { method: "POST", body: inventory, gzip: true, timeoutMs: 60000 });
  const failOn = SEVERITY_RANK[opt["fail-on"] ?? "high"] ?? SEVERITY_RANK.high;
  const introduced = findings.filter((f) => f.introduced);
  const existing = findings.filter((f) => !f.introduced);
  const row = (f) => `| ${f.severity} | [${f.id}](${f.url}) ${f.title} | ${f.level.replace("_", " ")} | ${f.evidence.filter((e) => e.introduced || !f.introduced).slice(0, 3).map((e) => `\`${e.label}\` (${e.location})`).join(", ")} |`;
  const table = (list) => ["| Severity | Incident | Match | Where |", "|---|---|---|---|", ...list.map(row)].join("\n");
  const md = [
    "<!-- pharon-pr-check -->",
    "### 🔦 Pharon",
    introduced.length ? `**This pull request introduces ${introduced.length} component${introduced.length === 1 ? "" : "s"} with an open security incident.**\n\n${table(introduced)}` : "✅ This pull request introduces no component with an open security incident.",
    existing.length ? `\n<details><summary>Already on the default branch: ${existing.length} open incident${existing.length === 1 ? "" : "s"}</summary>\n\n${table(existing)}\n</details>` : "",
  ].join("\n");

  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${md}\n`);
  for (const f of introduced) {
    const level = SEVERITY_RANK[f.severity] >= failOn ? "error" : "warning";
    const e = f.evidence.find((x) => x.introduced);
    console.log(`::${level} file=${(e?.location ?? "").replace(/:\d+$/, "")},title=Pharon ${f.severity}::${f.id}: ${f.title} (${e?.label})`);
  }
  if (opt.comment && facts.pr) await prComment(facts.pr.number, md, introduced.length > 0).catch((err) => console.log(`::warning::Pharon couldn't comment on the PR: ${err.message}`));
  console.log(introduced.length ? `${introduced.length} introduced finding(s).` : "No introduced findings.");
  if (introduced.some((f) => SEVERITY_RANK[f.severity] >= failOn)) process.exitCode = 1;
}

/** One comment per PR, updated in place (marker), so pushes don't pile up comments. Needs pull-requests: write. */
async function prComment(number, body, hasFindings) {
  const token = process.env.GITHUB_TOKEN;
  if (!token) throw new Error("GITHUB_TOKEN is not set");
  const base = `${process.env.GITHUB_API_URL ?? "https://api.github.com"}/repos/${process.env.GITHUB_REPOSITORY}`;
  const gh = async (url, init = {}) => {
    const res = await fetch(url, { ...init, signal: AbortSignal.timeout(15000), headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "content-type": "application/json", "user-agent": `pharon-cli/${cfg.VERSION}` } });
    if (!res.ok) throw new Error(`GitHub ${res.status}`);
    return res.json();
  };
  // Only our own comment (written by the workflow token, i.e. github-actions[bot]): anyone can paste the marker.
  let mine = null;
  for (let page = 1; page <= 10 && !mine; page++) {
    const comments = await gh(`${base}/issues/${number}/comments?per_page=100&page=${page}`);
    mine = comments.find((c) => c.user?.login === "github-actions[bot]" && c.body?.includes("<!-- pharon-pr-check -->"));
    if (comments.length < 100) break;
  }
  if (mine) await gh(`${base}/issues/comments/${mine.id}`, { method: "PATCH", body: JSON.stringify({ body }) });
  else if (hasFindings) await gh(`${base}/issues/${number}/comments`, { method: "POST", body: JSON.stringify({ body }) });
}

async function notices() {
  const ctx = context();
  if (!ctx.link) fail("This repo isn't linked yet. Run /pharon:setup.");
  const list = await refreshNotices(ctx);
  if (opt.json) return console.log(JSON.stringify(list, null, 2));
  console.log(list.length ? list.map((n) => `- ${n.text}`).join("\n") : "No notices for this repo.");
}

const COMMANDS = { login, link, sync, show, status, check, services, notices, gaps, track, manual, ci, redact: redactCmd, queue: () => (positionals[1] === "flush" ? flushQueue() : fail("Usage: pharon queue flush")) };

export async function main() {
  const cmd = positionals[0];
  if (opt.version) return console.log(cfg.VERSION);
  if (!cmd || opt.help || !COMMANDS[cmd]) return console.log(HELP);
  try {
    await COMMANDS[cmd]();
  } catch (e) {
    cfg.log(`error ${cmd}${opt.hook ? ` hook=${opt.hook}` : ""}: ${e.stack ?? e}`);
    if (opt.hook) return; // never disturb the Claude Code session; details are in ~/.pharon/logs
    console.error(e instanceof UserError ? e.message : e.status === 401 ? "Not logged in (or the token was revoked). Run `pharon login`." : `pharon: ${e.message}`);
    process.exitCode = 1;
  }
}
