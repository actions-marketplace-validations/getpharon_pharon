import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

// Fake gcloud and az on PATH (never touch real clouds in tests); every call is logged.
const dir = mkdtempSync(path.join(tmpdir(), "pharon-gcp-az-"));
const log = path.join(dir, "calls.log");
const fake = (name, body) => writeFileSync(path.join(dir, name), `#!/usr/bin/env node
const fs = require("fs"); const a = process.argv.slice(2); fs.appendFileSync(${JSON.stringify(log)}, "${name} " + a.join(" ") + "\\n");
const has = (x) => a.includes(x); const val = (f) => a[a.indexOf(f) + 1];
const out = (o) => (process.stdout.write(JSON.stringify(o)), process.exit(0));
const err = (m, c = 1) => (process.stderr.write(m), process.exit(c));
${body}
out([]);
`, { mode: 0o755 });
fake("gcloud", `
if (a[0] === "config") out({ core: { account: "dev@acme.com", project: "acme-prod" } });
if (a[0] === "projects") out([{ projectId: "acme-prod", name: "Acme prod" }, { projectId: "acme-dev", name: "Acme dev" }]);
if (val("--project") === "acme-dev" && a[0] !== "services") err("ERROR: (gcloud) There was a problem refreshing your current auth tokens: invalid_grant");
if (a[0] === "services") out([{ config: { name: "sqladmin.googleapis.com" } }, { config: { name: "container.googleapis.com" } }, { config: { name: "cloudfunctions.googleapis.com" } }, { config: { name: "redis.googleapis.com" } }, { config: { name: "run.googleapis.com" } }]);
if (a[0] === "run") out([{ spec: { template: { spec: { containers: [{ image: "europe-docker.pkg.dev/acme-prod/web/api:1.4.2" }] } } } }]);
if (a[0] === "sql") out([{ name: "db", region: "europe-west1", databaseVersion: "POSTGRES_15", maintenanceVersion: "POSTGRES_15_4.R20230830.01_00", selfLink: "https://x/acme-prod/db" }]);
if (a[0] === "container") out([{ name: "k", location: "europe-west1", currentMasterVersion: "1.27.3-gke.100" }]);
if (a[0] === "functions") out([{ name: "projects/acme-prod/locations/europe-west1/functions/f", buildConfig: { runtime: "python312" } }]);
if (a[0] === "redis") err("ERROR: (gcloud.redis.instances.list) PERMISSION_DENIED: caller lacks redis.instances.list");
`);
fake("az", `
if (a[0] === "account") out([{ id: "11111111-2222-3333-4444-555555555555", name: "Production", state: "Enabled" }, { id: "x", name: "Old", state: "Disabled" }]);
if (a[0] === "resource") out([{ type: "Microsoft.DBforPostgreSQL/flexibleServers", location: "westeurope" }, { type: "Microsoft.ContainerService/managedClusters", location: "westeurope" }, { type: "Microsoft.Storage/storageAccounts", location: "westeurope" }, { type: "Microsoft.Storage/storageAccounts", location: "westeurope" }]);
if (a[0] === "postgres") out([{ id: "/subscriptions/1111/rg/x/pg", location: "westeurope", version: "16" }]);
if (a[0] === "aks") err("Could not connect to the endpoint (timed out)");
`);
process.env.PATH = `${dir}:${process.env.PATH}`;
const { azureStatus, gcpStatus, scanAzure, scanGcp, gcloud } = await import("./cloud-other.mjs");

test("gcloud: status, scan with versions, denial -> gap, expired login -> error", async () => {
  const st = await gcpStatus("s1");
  assert.equal(st.status, "logged_in");
  assert.equal(st.account_hint, "d…@acme.com");
  assert.deepEqual(st.projects.map((p) => p.id), ["acme-prod", "acme-dev"]);
  const r = await scanGcp("acme-prod", "s1");
  assert.deepEqual(r.components.filter((c) => c.type === "cloud_resource").map((c) => `${c.service}:${c.engine}:${c.version}`).sort(), ["cloudsql:postgres:15.4", "functions:python312:null", "gke:kubernetes:1.27.3"]);
  assert.deepEqual(r.components.filter((c) => c.type === "runtime").map((c) => `${c.name} ${c.version}`), ["python 3.12"]);
  assert.deepEqual(r.gaps.map((g) => `${g.provider}:${g.reason}`), ["google-cloud:permission_denied"]);
  assert.deepEqual(r.components.filter((c) => c.type === "container_image").map((c) => `${c.name}:${c.tag}`), [`europe-docker.pkg.dev/${r.account_ref}/web/api:1.4.2`]);
  assert.ok(!JSON.stringify(r.components).includes("acme-prod"), "project ids are hashed, image paths included");
  assert.equal((await scanGcp("acme-dev", "s1")).error, "expired");
  await assert.rejects(gcloud(["sql", "instances", "delete"]), /non-allowlisted/);
});

test("az: enabled subscriptions, versions, discovery of other resource types, network failure kept as failed", async () => {
  const st = await azureStatus("s1");
  assert.deepEqual(st.subscriptions.map((x) => x.name), ["Production"]);
  const r = await scanAzure("11111111-2222-3333-4444-555555555555", "s1");
  const res = r.components.map((c) => `${c.service}:${c.engine}:${c.version}`).sort();
  assert.deepEqual(res, ["Microsoft.Storage/storageAccounts:null:null", "postgresql:postgres:16"], "storage collapsed to one entry per type and region");
  assert.deepEqual(r.failed, ["aks|*"], "AKS timed out: kept as failed, not 'no clusters'");
  assert.ok(!readFileSync(log, "utf8").includes("mysql"), "only resource types that exist are scanned");
});
