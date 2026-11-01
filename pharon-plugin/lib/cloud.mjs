// Cloud discovery with the user's own CLI credentials (spec §7.2). Credentials never leave the machine and are
// never read by Pharon: we call the AWS CLI, which uses its normal credential chain (profiles, SSO, env).
import { execFile } from "node:child_process";
import { createHash, scryptSync } from "node:crypto";
import { existsSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);

/** Is an executable on the PATH? Checked without running it. */
export const which = (cmd) => (process.env.PATH ?? "").split(path.delimiter).some((d) => d && existsSync(path.join(d, cmd)));

// The only AWS operations Pharon can ever run, through the CLI or the server's SDK: read-only (spec §2.6, §9.4).
// API name -> AWS CLI command. Anything else throws. The read-only IAM role template lists the same actions.
export const AWS_OPS = {
  "sts:GetCallerIdentity": "sts get-caller-identity",
  "ec2:DescribeRegions": "ec2 describe-regions",
  "ec2:DescribeInstances": "ec2 describe-instances",
  "ce:GetCostAndUsage": "ce get-cost-and-usage",
  "rds:DescribeDBInstances": "rds describe-db-instances",
  "rds:DescribeDBClusters": "rds describe-db-clusters",
  "eks:ListClusters": "eks list-clusters",
  "eks:DescribeCluster": "eks describe-cluster",
  "lambda:ListFunctions": "lambda list-functions",
  "elasticache:DescribeCacheClusters": "elasticache describe-cache-clusters",
  "memorydb:DescribeClusters": "memorydb describe-clusters",
  "es:ListDomainNames": "opensearch list-domain-names",
  "es:DescribeDomains": "opensearch describe-domains",
  "mq:ListBrokers": "mq list-brokers",
  "mq:DescribeBroker": "mq describe-broker",
  "kafka:ListClustersV2": "kafka list-clusters-v2",
  "ecs:ListClusters": "ecs list-clusters",
  "ecs:ListTasks": "ecs list-tasks",
  "ecs:DescribeTasks": "ecs describe-tasks",
};

// Some list calls return more than we need, including secrets (Lambda environment variables, ECS env overrides):
// --query keeps only the fields the scanner reads, inside the aws process.
const KEEP = {
  "lambda:ListFunctions": "{Functions: Functions[].{FunctionArn: FunctionArn, Runtime: Runtime}}",
  "ecs:DescribeTasks": "{tasks: tasks[].{containers: containers[].{image: image}}}",
};
const AWS_ALLOWED = new Set([...Object.values(AWS_OPS), "configure list-profiles"]);

export class AwsError extends Error {
  constructor(op, stderr) {
    super(`${op}: ${stderr.trim().split("\n").at(-1)}`);
    this.kind = /AccessDenied|UnauthorizedOperation|not authorized/i.test(stderr)
      ? "permission_denied"
      : /expired|ExpiredToken|SSO session|refresh failed/i.test(stderr)
        ? "expired"
        : /Unable to locate credentials|could not be found|NoCredentials/i.test(stderr)
          ? "not_logged_in"
          : /Could not connect|EndpointConnectionError|timed out|TimeoutError|Connection reset|socket hang up|Name or service not known|ETIMEDOUT|ECONNRESET|EAI_AGAIN|ENOTFOUND/i.test(stderr)
            ? "network"
            : /OptInRequired|not subscribed|not available in this region/i.test(stderr)
              ? "unavailable"
              : "error";
  }
}

export async function aws(args, { profile, region, json = true, timeout = 30000 } = {}) {
  const op = args.slice(0, 2).join(" ");
  if (!AWS_ALLOWED.has(op)) throw new Error(`refusing to run a non-allowlisted AWS operation: ${op}`);
  const full = [...args, ...(json ? ["--output", "json"] : []), ...(profile ? ["--profile", profile] : []), ...(region ? ["--region", region] : [])];
  try {
    const { stdout } = await run("aws", full, { timeout, maxBuffer: 64 * 1024 * 1024, env: { ...process.env, AWS_PAGER: "" } });
    return json ? JSON.parse(stdout || "{}") : stdout;
  } catch (e) {
    throw new AwsError(op, String(e.stderr ?? e.message));
  }
}

/** Salted hash of a resource id (spec §6): the server never sees raw ids. */
export const ref = (prefix, id, salt) => `${prefix}-${createHash("sha256").update(`${salt}:${id}`).digest("hex").slice(0, 12)}`;

// Account ids are only 12 digits: a fast hash could be brute-forced by anyone holding the salt (including us).
// scrypt makes each guess cost ~0.1 s, so the 10^12 space is out of reach.
const accountRefs = new Map();
export function accountRef(accountId, salt) {
  if (!salt) throw new Error("no org salt yet: refusing to hash account ids without it");
  const k = `${salt}:${accountId}`;
  if (!accountRefs.has(k)) accountRefs.set(k, `acct-${scryptSync(String(accountId), `pharon-account:${salt}`, 6, { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }).toString("hex")}`);
  return accountRefs.get(k);
}

/** Which AWS profiles exist and which are logged in. Asks the AWS CLI; never opens ~/.aws/credentials. */
export async function awsStatus(salt) {
  if (!which("aws")) return { installed: false, profiles: [] };
  const names = (await aws(["configure", "list-profiles"], { json: false }).catch(() => "")).split("\n").map((s) => s.trim()).filter(Boolean);
  // Keys set only in the environment: no --profile flag (profile ""), shown as "(environment)".
  if (!names.length && process.env.AWS_ACCESS_KEY_ID) names.push("");
  const profiles = await Promise.all(
    names.slice(0, 20).map(async (profile) => {
      const name = profile || "(environment)";
      try {
        const id = await aws(["sts", "get-caller-identity"], { profile: profile || undefined, timeout: 15000 });
        return { name, profile, status: "logged_in", account_id: id.Account, account_hint: `${id.Account.slice(0, 4)}…`, account_ref: salt ? accountRef(id.Account, salt) : null };
      } catch (e) {
        return { name, profile, status: e.kind ?? "error" };
      }
    }),
  );
  return { installed: true, profiles };
}

/** Other provider CLIs: detected only (spec §9.1 step 3), never run. */
export const otherTools = () => Object.fromEntries(["gcloud", "az", "kubectl", "flyctl", "vercel", "supabase", "doctl"].map((t) => [t, { installed: which(t) }]));

// ---------- AWS scan ----------

const CE_SERVICES = {
  "Amazon Relational Database Service": "rds",
  "Amazon DocumentDB (with MongoDB compatibility)": "rds",
  "AWS Lambda": "lambda",
  "Amazon Elastic Kubernetes Service": "eks",
  "Amazon ElastiCache": "elasticache",
  "Amazon MemoryDB": "memorydb",
  "Amazon OpenSearch Service": "opensearch",
  "Amazon MQ": "mq",
  "Amazon Managed Streaming for Apache Kafka": "kafka",
  "Amazon Elastic Container Service": "ecs",
  "Amazon Elastic Compute Cloud - Compute": "ec2",
  EC2: "ec2",
};
const SCANNERS = ["rds", "lambda", "eks", "elasticache", "memorydb", "opensearch", "mq", "kafka", "ecs", "ec2"];
const LAMBDA_RUNTIMES = { nodejs: "node", python: "python", java: "java", dotnet: "dotnet", ruby: "ruby" };

/** Run async jobs with bounded parallelism (each AWS CLI call is a process). */
async function pool(jobs, size = 6) {
  const out = [];
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(size, jobs.length) }, async () => {
    while (i < jobs.length) out.push(await jobs[i++]());
  }));
  return out.flat();
}

/** The CLI transport: AWS API name + params -> `aws <service> <command> --cli-input-json` (same shapes as the SDK). */
export const cliCaller = (profile) => (op, params, region) =>
  aws([...AWS_OPS[op].split(" "), ...(params ? ["--cli-input-json", JSON.stringify(params)] : []), ...(KEEP[op] ? ["--query", KEEP[op]] : [])], { profile: profile || undefined, region });

/** Scan one AWS account through a local profile (spec §7.2). */
export const scanAws = (profile, salt, opts = {}) => scanAwsWith(cliCaller(profile), salt, opts);

/**
 * Scan one AWS account through `call(op, params, region)` (the CLI on developer machines). Returns
 * { components, gaps, failed } or { error } when the account can't be used at all (expired login...).
 */
export async function scanAwsWith(call0, salt, { now = new Date() } = {}) {
  const observedAt = now.toISOString();
  let account;
  try {
    account = (await call0("sts:GetCallerIdentity")).Account;
  } catch (e) {
    return { error: e.kind ?? "error", message: e.message };
  }
  const acctRef = accountRef(account, salt);
  const components = [];
  const gaps = [];
  const failed = new Set(); // "service|region" pairs whose calls failed: keep the previous data for them
  const prov = (method) => ({ source: "cloud_cli", method, verified: true, observed_at: observedAt });
  const resource = (service, region, arn, engine, version, method) =>
    components.push({ type: "cloud_resource", provider: "aws", service, engine: engine ?? null, version: version ?? null, account_ref: acctRef, region, resource_ref: ref("res", arn ?? `${service}:${region}`, salt), provenance: prov(method), _scan: `${service}|${region}` });
  const call = async (op, params, region) => {
    const service = AWS_OPS[op].split(" ")[0];
    try {
      return await call0(op, params, region);
    } catch (e) {
      if (e.kind === "permission_denied") gaps.push({ id: `aws-denied-${service}-${region ?? "global"}`, provider: "aws", reason: "permission_denied", service, region: region ?? null, account_ref: acctRef });
      else if (e.kind !== "unavailable") failed.add(`${service}|${region ?? "global"}`); // network or unexpected: not "nothing there"
      return null;
    }
  };

  // 1. Discovery: what this account used in the last 30 days, by service and region.
  const end = observedAt.slice(0, 10);
  const start = new Date(now.getTime() - 30 * 864e5).toISOString().slice(0, 10);
  const ce = await call("ce:GetCostAndUsage", { TimePeriod: { Start: start, End: end }, Granularity: "MONTHLY", Metrics: ["UnblendedCost"], GroupBy: [{ Type: "DIMENSION", Key: "SERVICE" }, { Type: "DIMENSION", Key: "REGION" }] }, "us-east-1");
  let targets; // [service, region]
  if (ce) {
    const pairs = new Set();
    for (const r of ce.ResultsByTime ?? [])
      for (const g of r.Groups ?? []) {
        const [svc, region] = g.Keys ?? [];
        // Every returned service is in use, even at $0 (free tier, credits).
        const slug = CE_SERVICES[svc];
        if (slug && region && region !== "global" && region !== "NoRegion") pairs.add(`${slug}|${region}`);
        else if (!slug) components.push({ type: "cloud_resource", provider: "aws", service: svc.slice(0, 120), engine: null, version: null, account_ref: acctRef, region: region || null, resource_ref: null, provenance: prov("aws:ce:GetCostAndUsage"), _scan: "ce|us-east-1" });
      }
    targets = [...pairs].map((p) => p.split("|"));
  } else if (failed.has("ce|us-east-1")) {
    return { error: "network", message: "Cost Explorer unreachable: can't tell what exists, keeping the previous scan" };
  } else {
    // Fallback (Cost Explorer denied): every core scanner in every enabled region.
    const regions = (await call("ec2:DescribeRegions", { Filters: [{ Name: "opt-in-status", Values: ["opt-in-not-required", "opted-in"] }] }, "us-east-1"))?.Regions?.map((r) => r.RegionName);
    if (!regions) return { error: "network", message: "couldn't list regions, keeping the previous scan" };
    targets = regions.flatMap((r) => SCANNERS.map((s) => [s, r]));
  }

  // 2. Versions: read-only describe calls per (service, region).
  const scan = {
    rds: async (r) => {
      for (const i of (await call("rds:DescribeDBInstances", null, r))?.DBInstances ?? []) if (!i.DBClusterIdentifier) resource("rds", r, i.DBInstanceArn, i.Engine, i.EngineVersion, "aws:rds:DescribeDBInstances");
      for (const c of (await call("rds:DescribeDBClusters", null, r))?.DBClusters ?? []) resource("rds", r, c.DBClusterArn, c.Engine, c.EngineVersion, "aws:rds:DescribeDBClusters");
    },
    lambda: async (r) => {
      for (const f of (await call("lambda:ListFunctions", null, r))?.Functions ?? []) {
        resource("lambda", r, f.FunctionArn, f.Runtime ?? "container", null, "aws:lambda:ListFunctions");
        const m = f.Runtime?.match(/^([a-z]+?)(\d+(?:\.\d+)?)/);
        if (m && LAMBDA_RUNTIMES[m[1]]) components.push({ type: "runtime", name: LAMBDA_RUNTIMES[m[1]], version: m[2], locations: [`aws:lambda:${r}`], provenance: prov("aws:lambda:ListFunctions"), _scan: `lambda|${r}` });
      }
    },
    eks: async (r) => {
      for (const name of (await call("eks:ListClusters", null, r))?.clusters ?? []) {
        const c = (await call("eks:DescribeCluster", { name }, r))?.cluster;
        if (c) resource("eks", r, c.arn, "kubernetes", c.version, "aws:eks:DescribeCluster");
      }
    },
    elasticache: async (r) => {
      for (const c of (await call("elasticache:DescribeCacheClusters", null, r))?.CacheClusters ?? []) resource("elasticache", r, c.ARN, c.Engine, c.EngineVersion, "aws:elasticache:DescribeCacheClusters");
    },
    memorydb: async (r) => {
      for (const c of (await call("memorydb:DescribeClusters", null, r))?.Clusters ?? []) resource("memorydb", r, c.ARN, c.Engine ?? "redis", c.EngineVersion, "aws:memorydb:DescribeClusters");
    },
    opensearch: async (r) => {
      const names = ((await call("es:ListDomainNames", null, r))?.DomainNames ?? []).map((d) => d.DomainName);
      for (let i = 0; i < names.length; i += 5)
        for (const d of (await call("es:DescribeDomains", { DomainNames: names.slice(i, i + 5) }, r))?.DomainStatusList ?? []) {
          const [engine, version] = String(d.EngineVersion ?? "").split("_");
          resource("opensearch", r, d.ARN, engine?.toLowerCase() || "opensearch", version ?? null, "aws:opensearch:DescribeDomains");
        }
    },
    mq: async (r) => {
      for (const b of (await call("mq:ListBrokers", null, r))?.BrokerSummaries ?? []) {
        const d = await call("mq:DescribeBroker", { BrokerId: b.BrokerId }, r);
        resource("mq", r, b.BrokerArn, String(b.EngineType ?? d?.EngineType ?? "").toLowerCase(), d?.EngineVersion, "aws:mq:DescribeBroker");
      }
    },
    kafka: async (r) => {
      for (const c of (await call("kafka:ListClustersV2", null, r))?.ClusterInfoList ?? []) resource("kafka", r, c.ClusterArn, "kafka", c.Provisioned?.CurrentBrokerSoftwareInfo?.KafkaVersion, "aws:kafka:ListClustersV2");
    },
    ecs: async (r) => {
      // Running tasks' images (DescribeTasks), not task definitions: definitions carry environment variables.
      for (const cluster of (await call("ecs:ListClusters", null, r))?.clusterArns ?? []) {
        const tasks = (await call("ecs:ListTasks", { cluster }, r))?.taskArns ?? [];
        for (let i = 0; i < tasks.length; i += 100)
          for (const t of (await call("ecs:DescribeTasks", { cluster, tasks: tasks.slice(i, i + 100) }, r))?.tasks ?? [])
            for (const c of t.containers ?? []) {
              const [main, digest = null] = String(c.image).split("@");
              const at = main.lastIndexOf(":") > main.lastIndexOf("/") ? main.lastIndexOf(":") : -1;
              // ECR names embed the registry's account id: hash it like any account id.
              const name = (at > 0 ? main.slice(0, at) : main).replace(/^(\d{12})(?=\.dkr\.ecr\.)/, (id) => accountRef(id, salt));
              components.push({ type: "container_image", name, tag: at > 0 ? main.slice(at + 1) : digest ? null : "latest", digest, locations: [`aws:ecs:${r}`], provenance: prov("aws:ecs:DescribeTasks"), _scan: `ecs|${r}` });
            }
      }
    },
    ec2: async (r) => {
      for (const res of (await call("ec2:DescribeInstances", null, r))?.Reservations ?? [])
        for (const i of res.Instances ?? []) resource("ec2", r, i.InstanceId, i.PlatformDetails ?? "Linux/UNIX", null, "aws:ec2:DescribeInstances");
    },
  };
  await pool(targets.filter(([s]) => scan[s]).map(([s, r]) => () => scan[s](r)));
  return { account_ref: acctRef, account_id: account, observed_at: observedAt, components, gaps, failed: [...failed] };
}
