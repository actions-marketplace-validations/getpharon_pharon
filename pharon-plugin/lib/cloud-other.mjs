// Google Cloud and Azure discovery through the user's own gcloud / az CLI (spec §7.2, same model as AWS).
// Read-only allowlisted commands only; project and subscription ids are hashed like AWS account ids.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { accountRef, ref, which } from "./cloud.mjs";

const run = promisify(execFile);

const GCLOUD_ALLOWED = ["config list", "projects list", "services list", "sql instances list", "container clusters list", "functions list", "run services list", "redis instances list"];
const AZ_ALLOWED = ["account list", "resource list", "postgres flexible-server list", "mysql flexible-server list", "aks list", "redis list"];

const classify = (s) =>
  /PERMISSION_DENIED|AuthorizationFailed|does not have permission|not authorized|\b403\b/i.test(s)
    ? "permission_denied"
    : /Reauthentication|invalid_grant|problem refreshing|AADSTS\d+|token.*expired|expired.*token/i.test(s)
      ? "expired"
      : /active account|az login|not logged in|No subscription/i.test(s)
        ? "not_logged_in"
        : /has not been used in project|is not enabled|SERVICE_DISABLED|not enabled|NoRegisteredProviderFound/i.test(s)
          ? "unavailable"
          : /Could not connect|timed out|ETIMEDOUT|ECONNRESET|EAI_AGAIN|ENOTFOUND|ConnectionError|Name or service not known/i.test(s)
            ? "network"
            : "error";

export class CloudCliError extends Error {
  constructor(tool, cmd, stderr) {
    super(`${tool} ${cmd}: ${stderr.trim().split("\n").at(-1)}`);
    this.kind = classify(stderr);
  }
}

async function cli(tool, allowed, words, extra = []) {
  const cmd = words.join(" ");
  if (!allowed.includes(cmd)) throw new Error(`refusing to run a non-allowlisted ${tool} command: ${cmd}`);
  const args = [...words, ...extra, ...(tool === "gcloud" ? ["--format=json", "--quiet"] : ["--output", "json", "--only-show-errors"])];
  try {
    // Never let the CLI prompt (az may offer to install an extension): a hook's background run has no terminal.
    const env = { ...process.env, CLOUDSDK_CORE_DISABLE_PROMPTS: "1", AZURE_EXTENSION_USE_DYNAMIC_INSTALL: "no", AZURE_CORE_NO_COLOR: "1" };
    const { stdout } = await run(tool, args, { timeout: 60000, maxBuffer: 64 * 1024 * 1024, env });
    return JSON.parse(stdout || "null");
  } catch (e) {
    throw new CloudCliError(tool, cmd, String(e.stderr || e.message));
  }
}
export const gcloud = (words, extra) => cli("gcloud", GCLOUD_ALLOWED, words, extra);
export const az = (words, extra) => cli("az", AZ_ALLOWED, words, extra);

/** gcloud installed? logged in? which projects (ids stay local, refs are salted hashes). */
export async function gcpStatus(salt) {
  if (!which("gcloud")) return { installed: false };
  try {
    const account = (await gcloud(["config", "list"]))?.core?.account;
    if (!account) return { installed: true, status: "not_logged_in" };
    const projects = (await gcloud(["projects", "list"])) ?? [];
    return { installed: true, status: "logged_in", account_hint: account.replace(/^(.).*(@.*)$/, "$1…$2"), projects: projects.map((p) => ({ id: p.projectId, name: p.name, account_ref: salt ? accountRef(p.projectId, salt) : null })) };
  } catch (e) {
    return { installed: true, status: e.kind ?? "error" };
  }
}

export async function azureStatus(salt) {
  if (!which("az")) return { installed: false };
  try {
    const subs = ((await az(["account", "list"])) ?? []).filter((s) => s.state === "Enabled");
    if (!subs.length) return { installed: true, status: "not_logged_in" };
    return { installed: true, status: "logged_in", subscriptions: subs.map((s) => ({ id: s.id, name: s.name, account_ref: salt ? accountRef(s.id, salt) : null })) };
  } catch (e) {
    return { installed: true, status: e.kind ?? "error" };
  }
}

// First command word -> the service name used in components, so a failed list keeps that service's previous data.
const SLUG = { sql: "cloudsql", container: "gke", functions: "functions", run: "run", redis: "redis", postgres: "postgresql", mysql: "mysql", aks: "aks", resource: "resource", services: "services" };

/** A scan context shared by both scanners: denials become gaps, network failures are reported, never "empty". */
function scanner(provider, salt, accountId, now, tool) {
  const observedAt = now.toISOString();
  const acct = accountRef(accountId, salt);
  const out = { account_ref: acct, account_id: accountId, observed_at: observedAt, components: [], gaps: [], failed: [] };
  const prov = (method) => ({ source: "cloud_cli", method, verified: true, observed_at: observedAt });
  return {
    out,
    prov,
    resource(service, region, id, engine, version, method) {
      out.components.push({ type: "cloud_resource", provider, service, engine: engine ?? null, version: version ?? null, account_ref: acct, region: region ?? null, resource_ref: ref("res", id ?? `${service}:${region}`, salt), provenance: prov(method), _scan: `${service}|${region ?? "global"}` });
    },
    async call(words, extra) {
      try {
        return await tool(words, extra);
      } catch (e) {
        if (e.kind === "permission_denied") out.gaps.push({ id: `${provider}-denied-${words.join("-")}`, provider: provider === "gcp" ? "google-cloud" : provider, reason: "permission_denied", service: words[0], account_ref: acct });
        else if (e.kind === "expired" || e.kind === "not_logged_in") throw e;
        else if (e.kind !== "unavailable") out.failed.push(`${provider === "gcp" && words[0] === "redis" ? "memorystore" : (SLUG[words[0]] ?? words[0])}|*`); // every region of that service
        return null;
      }
    },
  };
}

const GCF_RUNTIME = { nodejs: "node", python: "python", go: "go", java: "java", ruby: "ruby", php: "php", dotnet: "dotnet" };
/** nodejs20 -> node 20, python312 -> python 3.12, go122 -> go 1.22 (Cloud Functions / Run runtime ids). */
export function gcpRuntime(id) {
  const m = String(id ?? "").match(/^([a-z]+?)(\d+)$/);
  if (!m || !GCF_RUNTIME[m[1]]) return null;
  const digits = m[2];
  const version = ["python", "go", "ruby", "php"].includes(m[1]) && digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
  return { name: GCF_RUNTIME[m[1]], version };
}

/** Scan one Google Cloud project with the active gcloud account. */
export async function scanGcp(projectId, salt, { now = new Date() } = {}) {
  const s = scanner("gcp", salt, projectId, now, (words, extra = []) => gcloud(words, ["--project", projectId, ...extra]));
  try {
    const enabled = await s.call(["services", "list"], ["--enabled"]);
    if (!enabled && s.out.failed.length) return { error: "network", message: "couldn't list the project's services, keeping the previous scan" };
    const on = new Set((enabled ?? []).map((x) => x.config?.name ?? String(x.name ?? "").split("/").pop()));
    const want = (api) => !enabled || on.has(api);
    if (want("sqladmin.googleapis.com"))
      for (const i of (await s.call(["sql", "instances", "list"])) ?? []) {
        const [engine, ...major] = String(i.databaseVersion ?? "").split("_");
        const exact = String(i.maintenanceVersion ?? "").match(/^[A-Z]+_(\d+)_(\d+)/);
        s.resource("cloudsql", i.region, i.selfLink ?? i.name, engine.toLowerCase() || null, exact ? `${exact[1]}.${exact[2]}` : major.join(".") || null, "gcp:sql:instances.list");
      }
    if (want("container.googleapis.com"))
      for (const c of (await s.call(["container", "clusters", "list"])) ?? []) s.resource("gke", c.location, c.selfLink ?? c.name, "kubernetes", String(c.currentMasterVersion ?? "").split("-")[0] || null, "gcp:container:clusters.list");
    if (want("cloudfunctions.googleapis.com"))
      for (const f of (await s.call(["functions", "list"])) ?? []) {
        const runtimeId = f.runtime ?? f.buildConfig?.runtime;
        const region = String(f.name ?? "").split("/")[3] ?? null;
        s.resource("functions", region, f.name, runtimeId ?? "container", null, "gcp:functions:list");
        const rt = gcpRuntime(runtimeId);
        if (rt) s.out.components.push({ type: "runtime", ...rt, locations: [`gcp:functions:${region}`], provenance: s.prov("gcp:functions:list"), _scan: `functions|${region}` });
      }
    if (want("run.googleapis.com"))
      for (const svc of (await s.call(["run", "services", "list"])) ?? [])
        for (const c of svc.spec?.template?.spec?.containers ?? []) {
          const [main, digest = null] = String(c.image).split("@");
          const at = main.lastIndexOf(":") > main.lastIndexOf("/") ? main.lastIndexOf(":") : -1;
          // Artifact Registry / GCR paths embed the project id: hash it like the project itself.
          const name = (at > 0 ? main.slice(0, at) : main).split("/").map((seg) => (seg === projectId ? s.out.account_ref : seg)).join("/");
          s.out.components.push({ type: "container_image", name, tag: at > 0 ? main.slice(at + 1) : digest ? null : "latest", digest, locations: ["gcp:run"], provenance: s.prov("gcp:run:services.list"), _scan: "run|global" });
        }
    if (want("redis.googleapis.com"))
      for (const r of (await s.call(["redis", "instances", "list"], ["--region=-"])) ?? []) s.resource("memorystore", r.locationId, r.name, "redis", String(r.redisVersion ?? "").replace(/^REDIS_/, "").replace(/_/g, ".") || null, "gcp:redis:instances.list");
  } catch (e) {
    return { error: e.kind ?? "error", message: e.message };
  }
  return s.out;
}

const AZ_TYPES = {
  "microsoft.dbforpostgresql/flexibleservers": [["postgres", "flexible-server", "list"], "postgresql", (x) => ["postgres", x.version]],
  "microsoft.dbformysql/flexibleservers": [["mysql", "flexible-server", "list"], "mysql", (x) => ["mysql", x.version]],
  "microsoft.containerservice/managedclusters": [["aks", "list"], "aks", (x) => ["kubernetes", x.currentKubernetesVersion ?? x.kubernetesVersion]],
  "microsoft.cache/redis": [["redis", "list"], "redis", (x) => ["redis", x.redisVersion]],
};

/** Scan one Azure subscription with the logged-in az account. */
export async function scanAzure(subscriptionId, salt, { now = new Date() } = {}) {
  const s = scanner("azure", salt, subscriptionId, now, (words, extra = []) => az(words, ["--subscription", subscriptionId, ...extra]));
  try {
    const resources = await s.call(["resource", "list"]);
    if (!resources && s.out.failed.length) return { error: "network", message: "couldn't list the subscription's resources, keeping the previous scan" };
    const types = new Set((resources ?? []).map((r) => String(r.type).toLowerCase()));
    // Every resource type in use is part of the stack, even without a version scanner (like AWS Cost Explorer discovery).
    const seen = new Set();
    for (const r of resources ?? []) {
      const key = `${String(r.type).toLowerCase()}|${r.location}`;
      if (AZ_TYPES[String(r.type).toLowerCase()] || seen.has(key)) continue;
      seen.add(key);
      s.out.components.push({ type: "cloud_resource", provider: "azure", service: String(r.type).slice(0, 120), engine: null, version: null, account_ref: s.out.account_ref, region: r.location ?? null, resource_ref: null, provenance: s.prov("azure:resource:list"), _scan: "resource|global" });
    }
    for (const [type, [cmd, service, read]] of Object.entries(AZ_TYPES))
      if (!resources || types.has(type))
        for (const x of (await s.call(cmd)) ?? []) {
          const [engine, version] = read(x);
          s.resource(service, x.location, x.id, engine, version ? String(version) : null, `azure:${cmd.join(" ")}`);
        }
  } catch (e) {
    return { error: e.kind ?? "error", message: e.message };
  }
  return s.out;
}
