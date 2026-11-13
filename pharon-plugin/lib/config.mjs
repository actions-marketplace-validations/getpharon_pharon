import { execFileSync } from "node:child_process";
import { appendFileSync, chmodSync, closeSync, mkdirSync, openSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";

export const VERSION = "0.1.6"; // keep equal to package.json and plugin.json
export const HOME = process.env.PHARON_HOME ?? path.join(homedir(), ".pharon");

const safe = (s) => String(s).replace(/[^\w.-]+/g, "_");
const file = (...p) => path.join(HOME, ...p);

export function readJson(p, fallback = null) {
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return fallback;
  }
}
export function writeJson(p, data) {
  mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
  writeFileSync(p, JSON.stringify(data, null, 2), { mode: 0o600 });
}

export const config = () => readJson(file("config.json"), {});
export const saveConfig = (c) => writeJson(file("config.json"), { ...config(), ...c });
export const apiUrl = () => (process.env.PHARON_API_URL ?? config().api_url ?? "https://getpharon.com").replace(/\/+$/, "");

// Per repo (user-level, never committed): which project it is linked to and whether the first upload was confirmed.
export const linkPath = (repoId) => file("projects", `${safe(repoId)}.json`);
export const readLink = (repoId) => readJson(linkPath(repoId));
export const saveLink = (repoId, link) => writeJson(linkPath(repoId), link);

// Per repo + branch: last successful upload.
export const statePath = (repoId, branch) => file("state", safe(repoId), `${safe(branch)}.json`);
export const readState = (repoId, branch) => readJson(statePath(repoId, branch), {});
export const saveState = (repoId, branch, s) => writeJson(statePath(repoId, branch), { ...readState(repoId, branch), ...s });

// Offline queue: only the newest pending inventory per repo + branch is kept.
const queuePath = (repoId, branch) => file("queue", `${safe(repoId)}__${safe(branch)}.json`);
export const enqueue = (repoId, branch, item) => writeJson(queuePath(repoId, branch), item);
export const dequeue = (repoId, branch) => rmSync(queuePath(repoId, branch), { force: true });
export const queued = () => {
  try {
    return readdirSync(file("queue")).map((f) => ({ path: file("queue", f), ...readJson(file("queue", f), {}) }));
  } catch {
    return [];
  }
};

export function log(msg) {
  try {
    mkdirSync(file("logs"), { recursive: true, mode: 0o700 });
    appendFileSync(file("logs", "pharon.log"), `${new Date().toISOString()} ${msg}\n`);
  } catch {}
}

// ---- token storage: OS keychain, file fallback ----

const SERVICE = "pharon-cli";
const ACCOUNT = () => safe(apiUrl());

function run(cmd, args, input) {
  return execFileSync(cmd, args, { input, encoding: "utf8", stdio: ["pipe", "pipe", "ignore"], timeout: 5000 }).trim();
}

// Stored value: base64(JSON {access_token, refresh_token, expires_at}), so it survives `security -i` quoting.
export function saveCreds(t) {
  const blob = Buffer.from(JSON.stringify({ access_token: t.access_token, refresh_token: t.refresh_token, expires_at: Date.now() + (t.expires_in ?? 3600) * 1000 })).toString("base64");
  try {
    // Fed through stdin (`security -i`) so the secret never appears in the process list.
    if (process.env.PHARON_KEYCHAIN !== "0") {
      if (process.platform === "darwin") return run("security", ["-i"], `add-generic-password -U -a ${ACCOUNT()} -s ${SERVICE} -w ${blob}\n`), "keychain";
      if (process.platform === "linux") return run("secret-tool", ["store", "--label=Pharon CLI", "service", SERVICE, "account", ACCOUNT()], blob), "keychain";
    }
  } catch {}
  // shortcut: plaintext 0600 file when no keychain is available (headless Linux without libsecret, or PHARON_KEYCHAIN=0).
  writeJson(file("credentials.json"), { ...readJson(file("credentials.json"), {}), [ACCOUNT()]: blob });
  chmodSync(file("credentials.json"), 0o600);
  return "file";
}

function loadCreds() {
  let blob = null;
  try {
    if (process.env.PHARON_KEYCHAIN !== "0" && process.platform === "darwin") blob = run("security", ["find-generic-password", "-a", ACCOUNT(), "-s", SERVICE, "-w"]);
    else if (process.env.PHARON_KEYCHAIN !== "0" && process.platform === "linux") blob = run("secret-tool", ["lookup", "service", SERVICE, "account", ACCOUNT()]);
  } catch {}
  blob ??= readJson(file("credentials.json"), {})[ACCOUNT()] ?? null;
  try {
    return blob ? JSON.parse(Buffer.from(blob, "base64").toString("utf8")) : null;
  } catch {
    return null;
  }
}

const fresh = (c) => c?.access_token && c.expires_at - 60_000 > Date.now();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A valid access token, refreshing it (once, under a machine-wide lock) when it's about to expire. */
async function accessToken() {
  if (process.env.PHARON_TOKEN) return process.env.PHARON_TOKEN; // CI / tests
  let c = loadCreds();
  if (!c) throw new ApiError(401, { error: "not logged in" });
  if (fresh(c)) return c.access_token;
  const lock = file("refresh.lock");
  let locked = false;
  for (let i = 0; i < 50 && !locked; i++) {
    try {
      mkdirSync(HOME, { recursive: true, mode: 0o700 });
      closeSync(openSync(lock, "wx"));
      locked = true;
    } catch {
      try {
        if (Date.now() - statSync(lock).mtimeMs > 30_000) rmSync(lock, { force: true }); // crashed holder
      } catch {}
      await sleep(200);
    }
  }
  try {
    c = loadCreds(); // another process may have refreshed while we waited
    if (fresh(c)) return c.access_token;
    const res = await fetch(`${apiUrl()}/v1/auth/refresh`, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": `pharon-cli/${VERSION}` },
      body: JSON.stringify({ refresh_token: c.refresh_token }),
      signal: AbortSignal.timeout(15000),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const again = loadCreds();
      if (data?.error === "refresh_race" && fresh(again)) return again.access_token;
      throw new ApiError(res.status, data?.error === "invalid_grant" ? { error: "login expired or revoked" } : data);
    }
    saveCreds(data);
    return data.access_token;
  } finally {
    if (locked) rmSync(lock, { force: true });
  }
}

// ---- API ----

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.error ?? `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

export async function api(pathname, { method = "GET", body, headers = {}, auth = true, gzip = false, timeoutMs = 15000 } = {}) {
  const h = { "user-agent": `pharon-cli/${VERSION}`, ...headers };
  if (auth) {
    h.authorization = `Bearer ${await accessToken()}`;
  }
  let payload;
  if (body !== undefined) {
    h["content-type"] = "application/json";
    payload = JSON.stringify(body);
    if (gzip) {
      payload = gzipSync(payload);
      h["content-encoding"] = "gzip";
    }
  }
  const res = await fetch(apiUrl() + pathname, { method, headers: h, body: payload, signal: AbortSignal.timeout(timeoutMs) });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

