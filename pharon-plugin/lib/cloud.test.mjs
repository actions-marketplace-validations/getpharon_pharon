import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { aws, scanAws } from "./cloud.mjs";

// A fake `aws` on PATH: answers from fixtures, logs every call.
const dir = mkdtempSync(path.join(tmpdir(), "pharon-aws-"));
const log = path.join(dir, "calls.log");
const fixtures = {
  "ce get-cost-and-usage@us-east-1": { ResultsByTime: [{ Groups: [
    { Keys: ["Amazon Relational Database Service", "eu-west-1"], Metrics: { UnblendedCost: { Amount: "120.5" } } },
    { Keys: ["AWS Lambda", "eu-west-1"], Metrics: { UnblendedCost: { Amount: "3.1" } } },
    { Keys: ["Amazon Elastic Kubernetes Service", "us-east-1"], Metrics: { UnblendedCost: { Amount: "70" } } },
    { Keys: ["Amazon ElastiCache", "eu-west-1"], Metrics: { UnblendedCost: { Amount: "40" } } },
    { Keys: ["Amazon Elastic Container Service", "eu-west-1"], Metrics: { UnblendedCost: { Amount: "10" } } },
    { Keys: ["Amazon OpenSearch Service", "eu-west-1"], Metrics: { UnblendedCost: { Amount: "0" } } },
    { Keys: ["Amazon Simple Storage Service", "eu-west-1"], Metrics: { UnblendedCost: { Amount: "2" } } },
  ] }] },
  "rds describe-db-instances@eu-west-1": { DBInstances: [{ DBInstanceArn: "arn:aws:rds:eu-west-1:123456789012:db:main", Engine: "postgres", EngineVersion: "15.4" }, { DBInstanceArn: "arn:x:member", DBClusterIdentifier: "c1", Engine: "aurora-postgresql", EngineVersion: "16.1" }] },
  "rds describe-db-clusters@eu-west-1": { DBClusters: [{ DBClusterArn: "arn:aws:rds:eu-west-1:123456789012:cluster:c1", Engine: "aurora-postgresql", EngineVersion: "16.1" }] },
  "lambda list-functions@eu-west-1": { Functions: [{ FunctionArn: "arn:aws:lambda:eu-west-1:123456789012:function:a", Runtime: "nodejs20.x", Environment: { Variables: { OPENAI_API_KEY: "sk-live-secret" } } }, { FunctionArn: "arn:b", Runtime: "python3.12" }] },
  "eks list-clusters@us-east-1": { clusters: ["prod"] },
  "eks describe-cluster@us-east-1": { cluster: { arn: "arn:aws:eks:us-east-1:123456789012:cluster/prod", version: "1.29" } },
  "ecs list-clusters@eu-west-1": { clusterArns: ["arn:ecs:cluster/c"] },
  "ecs list-tasks@eu-west-1": { taskArns: ["arn:ecs:task/t1"] },
  "ecs describe-tasks@eu-west-1": { tasks: [{ containers: [{ image: "123456789012.dkr.ecr.eu-west-1.amazonaws.com/api:2.3.1" }, { image: "litellm/litellm:1.107.0" }] }] },
  denied: ["elasticache describe-cache-clusters@eu-west-1"],
};
writeFileSync(path.join(dir, "fixtures.json"), JSON.stringify(fixtures));
writeFileSync(path.join(dir, "aws"), `#!/usr/bin/env node
const fs = require("fs"); const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(log)}, args.join(" ") + "\\n");
const flag = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const op = args.slice(0, 2).join(" "), region = flag("--region");
if (flag("--profile") === "expired") { process.stderr.write("Token has expired and refresh failed"); process.exit(255); }
if (flag("--profile") === "flaky" && op !== "sts get-caller-identity" && op !== "ce get-cost-and-usage") { process.stderr.write("Could not connect to the endpoint URL"); process.exit(255); }
if (flag("--profile") === "offline" && op === "ce get-cost-and-usage") { process.stderr.write("Could not connect to the endpoint URL"); process.exit(255); }
if (op === "sts get-caller-identity") { process.stdout.write(JSON.stringify({ Account: "123456789012" })); process.exit(0); }
const F = JSON.parse(fs.readFileSync(${JSON.stringify(path.join(dir, "fixtures.json"))}, "utf8"));
const key = op + (region ? "@" + region : "");
if (F.denied.includes(key)) { process.stderr.write("An error occurred (AccessDeniedException): not authorized"); process.exit(254); }
process.stdout.write(JSON.stringify(F[key] ?? {}));
`, { mode: 0o755 });
process.env.PATH = `${dir}:${process.env.PATH}`;

test("scanAws: discovery via Cost Explorer, versions via describe calls, denials become gaps", async () => {
  const r = await scanAws("prod", "salt-1", { now: new Date("2026-10-25T09:00:00Z") });
  const res = r.components.filter((c) => c.type === "cloud_resource").map((c) => `${c.service}:${c.engine}:${c.version}@${c.region}`).sort();
  assert.deepEqual(res, [
    "Amazon Simple Storage Service:null:null@eu-west-1",
    "eks:kubernetes:1.29@us-east-1",
    "lambda:nodejs20.x:null@eu-west-1",
    "lambda:python3.12:null@eu-west-1",
    "rds:aurora-postgresql:16.1@eu-west-1",
    "rds:postgres:15.4@eu-west-1",
  ]);
  assert.deepEqual(r.components.filter((c) => c.type === "runtime").map((c) => `${c.name} ${c.version}`).sort(), ["node 20", "python 3.12"]);
  const images = r.components.filter((c) => c.type === "container_image").map((c) => `${c.name}:${c.tag}`).sort();
  assert.equal(images[1], "litellm/litellm:1.107.0");
  assert.match(images[0], /^acct-[0-9a-f]{12}\.dkr\.ecr\.eu-west-1\.amazonaws\.com\/api:2\.3\.1$/, "ECR registry account id hashed");
  assert.deepEqual(r.gaps.map((g) => g.id), ["aws-denied-elasticache-eu-west-1"]);
  assert.match(r.account_ref, /^acct-[0-9a-f]{12}$/);
  const json = JSON.stringify(r.components.filter((c) => c.type === "cloud_resource"));
  assert.ok(!json.includes("123456789012") && !json.includes("arn:"), "no raw account ids or ARNs on cloud resources");
  const calls = readFileSync(log, "utf8");
  assert.match(calls, /lambda list-functions .*--query \{Functions: Functions\[\]\.\{FunctionArn: FunctionArn, Runtime: Runtime\}\}/, "env vars filtered inside the aws process");
  assert.ok(!JSON.stringify(r).includes("sk-live-secret"));
  assert.ok(calls.includes("opensearch list-domain-names"), "services at $0 (free tier, credits) are still scanned");
  assert.deepEqual(r.failed, []);
});

test("network failures are reported as failed calls, never as 'nothing there'", async () => {
  const flaky = await scanAws("flaky", "salt-1", { now: new Date("2026-10-25T09:00:00Z") });
  assert.equal(flaky.error, undefined);
  assert.ok(flaky.failed.includes("rds|eu-west-1") && flaky.failed.includes("eks|us-east-1"));
  assert.equal(flaky.components.filter((c) => c.type === "cloud_resource" && c.service === "rds").length, 0);
  assert.equal((await scanAws("offline", "salt-1")).error, "network", "no discovery at all = keep the previous scan");
  await assert.rejects(() => scanAws("prod", ""), /salt/, "account ids are never hashed without the org salt");
});

test("expired login is reported, not thrown; non-allowlisted operations never run", async () => {
  assert.deepEqual((await scanAws("expired", "s")).error, "expired");
  await assert.rejects(aws(["rds", "delete-db-instance", "--db-instance-identifier", "x"]), /non-allowlisted/);
  await assert.rejects(aws(["s3", "cp", "a", "b"]), /non-allowlisted/);
});

