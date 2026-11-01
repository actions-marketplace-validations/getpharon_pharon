import { test } from "node:test";
import assert from "node:assert/strict";
import { detect } from "./detect.mjs";

const pkgs = (cs, eco) => cs.filter((c) => c.type === "package" && c.ecosystem === eco).map((c) => `${c.name}@${c.version ?? c.version_spec}${c.direct ? "" : " (t)"}`).sort();
const runtimes = (cs) => cs.filter((c) => c.type === "runtime").map((c) => `${c.name} ${c.version}`).sort();

test("go, rust, ruby, php", () => {
  const { components: cs } = detect(new Map([
    ["go.mod", "module github.com/acme/svc\n\ngo 1.22\n\nrequire (\n\tgithub.com/stripe/stripe-go/v76 v76.8.0\n\tgolang.org/x/net v0.21.0 // indirect\n)\n\nrequire github.com/redis/go-redis/v9 v9.5.1\n"],
    ["rs/Cargo.lock", 'version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.197"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "redis"\nversion = "0.25.2"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'],
    ["rs/Cargo.toml", '[package]\nname = "app"\n\n[dependencies]\nserde = "1.0"\n'],
    ["rs/rust-toolchain.toml", '[toolchain]\nchannel = "1.79.0"\n'],
    ["rb/Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.9)\n    rails (7.1.3)\n      rack (>= 2.2.4)\n    stripe (10.12.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails\n  stripe\n\nRUBY VERSION\n   ruby 3.3.0p0\n"],
    ["php/composer.lock", JSON.stringify({ packages: [{ name: "guzzlehttp/guzzle", version: "7.8.1" }, { name: "stripe/stripe-php", version: "v13.1.0" }], "packages-dev": [{ name: "phpunit/phpunit", version: "10.5.0" }] })],
    ["php/composer.json", JSON.stringify({ require: { php: ">=8.2", "stripe/stripe-php": "^13.0" } })],
  ]));
  assert.deepEqual(pkgs(cs, "go"), ["github.com/redis/go-redis/v9@v9.5.1", "github.com/stripe/stripe-go/v76@v76.8.0", "golang.org/x/net@v0.21.0 (t)"]);
  assert.deepEqual(pkgs(cs, "cargo"), ["redis@0.25.2 (t)", "serde@1.0.197"], "local crate skipped, direct from Cargo.toml");
  assert.deepEqual(pkgs(cs, "rubygems"), ["rack@3.0.9 (t)", "rails@7.1.3", "stripe@10.12.0"], "gem dependencies (6 spaces) aren't packages");
  assert.deepEqual(pkgs(cs, "packagist"), ["guzzlehttp/guzzle@7.8.1 (t)", "phpunit/phpunit@10.5.0 (t)", "stripe/stripe-php@13.1.0"]);
  assert.deepEqual(runtimes(cs), ["go 1.22", "php >=8.2", "ruby 3.3.0", "rust 1.79.0"]);
  const vendors = cs.filter((c) => c.type === "service").map((c) => c.vendor).sort();
  assert.deepEqual(vendors, ["redis", "stripe"], "service map covers go/ruby/php clients");
});

test("java and .NET", () => {
  const { components: cs } = detect(new Map([
    ["pom.xml", "<project><properties><jackson.version>2.16.1</jackson.version></properties><dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency><dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><version>42.7.2</version></dependency><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency></dependencies></project>"],
    ["g/gradle.lockfile", "# lockfile\ncom.google.guava:guava:33.0.0-jre=compileClasspath,runtimeClasspath\nempty=\n"],
    ["g/build.gradle.kts", 'dependencies {\n  implementation("com.google.guava:guava:33.0.0-jre")\n}\n'],
    ["n/packages.lock.json", JSON.stringify({ version: 1, dependencies: { "net8.0": { "Npgsql": { type: "Direct", resolved: "8.0.2" }, "Microsoft.Extensions.Logging": { type: "Transitive", resolved: "8.0.0" }, "Shared": { type: "Project" } } } })],
    ["n/App.csproj", '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Npgsql" Version="8.0.2" /></ItemGroup></Project>'],
  ]));
  assert.deepEqual(pkgs(cs, "maven"), ["com.fasterxml.jackson.core:jackson-databind@2.16.1", "com.google.guava:guava@33.0.0-jre", "org.postgresql:postgresql@42.7.2", "org.slf4j:slf4j-api@"]);
  assert.equal(cs.find((c) => c.name === "org.slf4j:slf4j-api").loose_range, true, "no version in pom: unknown, could be anything");
  assert.deepEqual(pkgs(cs, "nuget"), ["Microsoft.Extensions.Logging@8.0.0 (t)", "Npgsql@8.0.2"]);
  assert.deepEqual(runtimes(cs), ["dotnet 8.0"]);
});

test("terraform, serverless, SAM, platform configs", () => {
  const { components: cs, gaps } = detect(new Map([
    ["infra/main.tf", 'resource "aws_db_instance" "main" {\n  engine         = "postgres"\n  engine_version = "15.4"\n  tags = {\n    Name = "x"\n  }\n}\n\nresource "aws_elasticache_cluster" "cache" {\n  engine         = "redis"\n  engine_version = var.redis_version\n}\n\nresource "aws_eks_cluster" "k" {\n  version = "1.29"\n}\n\nresource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'],
    ["infra/prod.tfvars", 'db_password = "hunter2"\n'],
    ["infra/.terraform.lock.hcl", 'provider "registry.terraform.io/hashicorp/aws" {\n  version     = "5.40.0"\n  constraints = "~> 5.0"\n}\n'],
    ["serverless.yml", "service: api\nprovider:\n  name: aws\n  runtime: nodejs20.x\nfunctions:\n  job:\n    runtime: python3.12\n"],
    ["sam/template.yaml", "AWSTemplateFormatVersion: '2010-09-09'\nTransform: AWS::Serverless-2016-10-31\nResources:\n  Fn:\n    Properties:\n      Runtime: java21\n"],
    ["netlify.toml", '[build.environment]\n  NODE_VERSION = "20.11.1"\n'],
    ["fly.toml", 'app = "x"\n[build]\n  image = "ghcr.io/acme/web:1.4.2"\n'],
  ]));
  const cloud = cs.filter((c) => c.type === "cloud_resource").map((c) => `${c.provider}:${c.service}:${c.engine}:${c.version}`).sort();
  assert.deepEqual(cloud, ["aws:eks:kubernetes:1.29", "aws:elasticache:redis:null", "aws:rds:postgres:15.4"]);
  assert.deepEqual(gaps.map((g) => g.reason), ["version_from_variable"]);
  assert.deepEqual(pkgs(cs, "terraform"), ["hashicorp/aws@5.40.0"]);
  assert.deepEqual(runtimes(cs), ["java 21", "node 20", "node 20.11.1", "python 3.12"]);
  assert.ok(cs.some((c) => c.type === "container_image" && c.name === "ghcr.io/acme/web" && c.tag === "1.4.2"));
  assert.ok(!JSON.stringify(cs).includes("hunter2"), "tfvars are never read");
});
