import { test } from "node:test";
import assert from "node:assert/strict";
import { canonical, cmpVersion, satisfies, couldSatisfy, componentLevel } from "./match.mjs";

test("canonical json sorts keys and drops undefined", () => {
  assert.equal(canonical({ b: 1, a: [{ d: 2, c: undefined }], e: "x" }), '{"a":[{"d":2}],"b":1,"e":"x"}');
});

test("cmpVersion", () => {
  assert.equal(cmpVersion("1.107.0", "1.106.2"), 1);
  assert.equal(cmpVersion("1.2", "1.2.0"), 0);
  assert.equal(cmpVersion("2.0.0-beta.1", "2.0.0"), -1);
  assert.equal(cmpVersion("2.0.0rc1", "2.0.0a1"), 1);
  assert.equal(cmpVersion("v20.11.1", "20.9.0"), 1);
});

test("satisfies npm and pep440 specs", () => {
  assert.ok(satisfies(">=1.100", "1.107.0"));
  assert.ok(!satisfies(">=1.100,<1.107", "1.107.0"));
  assert.ok(satisfies("^1.2.3", "1.9.0"));
  assert.ok(!satisfies("^1.2.3", "2.0.0"));
  assert.ok(!satisfies("^0.2.3", "0.3.0"));
  assert.ok(satisfies("~1.2.3", "1.2.9"));
  assert.ok(!satisfies("~1.2.3", "1.3.0"));
  assert.ok(satisfies("~=1.4", "1.9"));
  assert.ok(!satisfies("~=1.4.5", "1.5.0"));
  assert.ok(satisfies("==1.2.*", "1.2.7"));
  assert.ok(satisfies("1.x || >=3", "3.1.0"));
  assert.ok(satisfies("20", "20.11.1"));
  assert.ok(!satisfies("20", "21.0.0"));
  assert.ok(satisfies(">= 1.0, < 2", "1.5"));
  assert.ok(satisfies("1.0.0 - 2.0.0", "2.0.0"));
  assert.ok(satisfies("", "9.9.9"));
  assert.ok(satisfies("workspace:*", "1.0.0"), "unknown syntax never rules out");
});

test("couldSatisfy with exact versions and ranges", () => {
  const exact = { versions: ["1.107.0"] };
  assert.ok(couldSatisfy(">=1.100", exact));
  assert.ok(!couldSatisfy("==1.106.2", exact));
  const range = { ranges: [{ introduced: "1.5.0", fixed: "1.8.0" }] };
  assert.ok(couldSatisfy("<2.0", range));
  assert.ok(couldSatisfy(">=1.0", range));
  assert.ok(!couldSatisfy(">=1.9", range));
});

test("componentLevel", () => {
  const a = { kind: "package", ecosystem: "pypi", name: "litellm", versions: ["1.107.0"] };
  const pkg = (o) => ({ type: "package", ecosystem: "pypi", name: "LiteLLM", ...o });
  assert.equal(componentLevel(pkg({ version: "1.107.0" }), a), "direct");
  assert.equal(componentLevel(pkg({ version: "1.106.2" }), a), "possible");
  assert.equal(componentLevel(pkg({ version: null, version_spec: ">=1.100" }), a), "likely");
  assert.equal(componentLevel(pkg({ version: null, version_spec: "<1.100" }), a), "possible");
  assert.equal(componentLevel({ ...pkg({ version: "1.107.0" }), ecosystem: "npm" }, a), null);

  const img = { kind: "container_image", name: "litellm/litellm", tags: ["1.107.0"] };
  assert.equal(componentLevel({ type: "container_image", name: "docker.io/litellm/litellm", tag: "1.107.0" }, img), "direct");
  assert.equal(componentLevel({ type: "container_image", name: "litellm/litellm", tag: "main" }, img), "possible");

  const node = { kind: "runtime", name: "node", ranges: [{ introduced: "20.0.0", fixed: "20.12.0" }] };
  assert.equal(componentLevel({ type: "runtime", name: "node", version: "20.11.1" }, node), "direct");
  assert.equal(componentLevel({ type: "runtime", name: "node", version: "20" }, node), "likely");
  assert.equal(componentLevel({ type: "runtime", name: "node", version: "22" }, node), "possible");

  const rds = { kind: "cloud_resource", provider: "aws", service: "rds", engine: "postgres", ranges: [{ introduced: "15.0", fixed: "15.6" }] };
  const db = (version) => ({ type: "cloud_resource", provider: "aws", service: "rds", engine: "postgres", version });
  assert.equal(componentLevel(db("15.4"), rds), "direct");
  assert.equal(componentLevel(db("16.1"), rds), "possible");
  assert.equal(componentLevel(db(null), rds), "likely");
  assert.equal(componentLevel({ ...db("15.4"), engine: "mysql" }, rds), null);
  const anyPg = { kind: "cloud_resource", engine: "postgres", ranges: [{ introduced: "15.0", fixed: "15.6" }] };
  assert.equal(componentLevel({ ...db("15.4"), provider: "supabase", service: "postgres" }, anyPg), "direct", "engine-level incident, any host");
  assert.equal(componentLevel({ ...db("15.4"), engine: "aurora-postgresql" }, anyPg), "direct", "aurora-postgresql is postgres");
  assert.equal(componentLevel({ ...db("15.4"), provider: "self", service: "vm", engine: "postgresql" }, anyPg), "direct", "a person typing postgresql");
  const redis = { kind: "cloud_resource", engine: "redis", ranges: [{ fixed: "7.2.5" }] };
  assert.equal(componentLevel({ type: "cloud_resource", provider: "aws", service: "elasticache", engine: "valkey", version: "8.0.1" }, redis), "likely", "related engine: never ruled out");
  const manual = { ...db("16.2"), provenance: { source: "manual", verified: false } };
  assert.equal(componentLevel(manual, rds), "manual_unverified", "a manual version never rules an incident out");

  assert.equal(componentLevel({ type: "service", vendor: "railway" }, { kind: "service", vendor: "railway" }), "likely");
  assert.equal(componentLevel({ type: "ci_action", name: "tj-actions/changed-files", ref: "v45" }, { kind: "ci_action", name: "tj-actions/changed-files", refs: ["v45"] }), "direct");
  const ranged = { kind: "ci_action", name: "acme/deploy", ranges: [{ fixed: "4.2.0" }] };
  const ref = (r) => componentLevel({ type: "ci_action", name: "acme/deploy", ref: r }, ranged);
  assert.deepEqual([ref("v4.1.9"), ref("v4.2.0"), ref("v4"), ref("v5"), ref("8f4b7f84864484a7bf31766abe9204da3cbe65b3")], ["direct", "possible", "likely", "possible", "possible"], "tag ranges: exact, fixed, floating major, newer major, SHA");
});
