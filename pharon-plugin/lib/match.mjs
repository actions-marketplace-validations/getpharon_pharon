// Shared by the CLI (`pharon check`) and the web app (matching engine), so both judge versions the same way.
// Pure functions, no dependencies.

/** Canonical JSON (sorted keys, no whitespace): the exact bytes that get signed and verified. */
export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

/** "*" wildcard match, case-insensitive, in linear time. No regex, so user or feed patterns can't cause ReDoS. */
export function globMatch(pattern, s) {
  const parts = String(pattern).toLowerCase().split("*");
  const str = String(s).toLowerCase();
  if (parts.length === 1) return str === parts[0];
  const first = parts[0];
  const last = parts.at(-1);
  if (str.length < first.length + last.length || !str.startsWith(first) || !str.endsWith(last)) return false;
  let pos = first.length;
  const end = str.length - last.length;
  for (const mid of parts.slice(1, -1)) {
    const i = str.indexOf(mid, pos);
    if (i === -1 || i + mid.length > end) return false;
    pos = i + mid.length;
  }
  return true;
}

// manual_unverified: a manual entry matched; its version is a claim, so it can't rule an incident out (spec §10.3).
export const LEVELS = ["preview_only", "possible", "manual_unverified", "likely", "direct"];
export const maxLevel = (a, b) => (!a ? b : !b ? a : LEVELS.indexOf(a) >= LEVELS.indexOf(b) ? a : b);

/** PEP 503 normalization for PyPI; everything else lowercased. */
export function normName(ecosystem, name) {
  const n = String(name).toLowerCase();
  return ecosystem === "pypi" ? n.replace(/[-_.]+/g, "-") : n;
}

export function normImage(name) {
  return String(name)
    .toLowerCase()
    .replace(/^(docker\.io|index\.docker\.io|registry-1\.docker\.io)\//, "")
    .replace(/^library\//, "");
}

/** Lookup key shared by components and incident `affects` entries (indexed server-side). */
export function matchKey(x) {
  const kind = x.kind ?? x.type;
  if (kind === "service") return `service:${String(x.vendor).toLowerCase()}`;
  if (kind === "container_image") return `image:${normImage(x.name)}`;
  if (kind === "package") return `package:${x.ecosystem}:${normName(x.ecosystem, x.name)}`;
  if (kind === "cloud_resource") return `cloud:${x.provider}:${x.service}:${x.engine ?? ""}`.toLowerCase();
  return `${kind}:${String(x.name).toLowerCase()}`;
}

// shortcut: dotted-numeric compare where any suffix is a pre-release; no PEP 440 epochs/post-releases. Upgrade if feed ranges need them.
export function cmpVersion(a, b) {
  const parse = (v) => {
    const m = String(v).trim().replace(/^v/i, "").split("+")[0].match(/^(\d+(?:\.\d+)*)(.*)$/);
    return m ? [m[1].split(".").map(Number), m[2].replace(/^[-.]/, "")] : [[0], String(v)];
  };
  const [an, ap] = parse(a);
  const [bn, bp] = parse(b);
  for (let i = 0; i < Math.max(an.length, bn.length); i++) {
    const d = (an[i] ?? 0) - (bn[i] ?? 0);
    if (d) return Math.sign(d);
  }
  if (ap === bp) return 0;
  if (!ap) return 1;
  if (!bp) return -1;
  return Math.sign(ap.localeCompare(bp, undefined, { numeric: true }));
}

const inRange = (v, r) =>
  (!r.introduced || cmpVersion(v, r.introduced) >= 0) &&
  (!r.fixed || cmpVersion(v, r.fixed) < 0) &&
  (!r.last_affected || cmpVersion(v, r.last_affected) <= 0);

/** Is this exact version affected? An affect with no versions and no ranges means "every version". */
export function affected(version, a) {
  if (!a.versions?.length && !a.ranges?.length) return true;
  return (a.versions ?? []).some((v) => cmpVersion(v, version) === 0) || (a.ranges ?? []).some((r) => inRange(version, r));
}

const nums = (v) => String(v).replace(/^v/i, "").split(/[.]/).filter((p) => /^\d+$/.test(p)).map(Number);
const bump = (parts, i) => [...parts.slice(0, i), (parts[i] ?? 0) + 1].join(".");

/** Expand one comparator token into [op, version] pairs. `null` = can't tell (treated as "could match anything"). */
function comparators(tok) {
  tok = tok.trim();
  if (!tok || tok === "*" || /^(x|latest)$/i.test(tok)) return [];
  let m;
  if ((m = tok.match(/^\^v?(.+)$/))) {
    const p = nums(m[1]);
    const i = p.findIndex((n) => n !== 0);
    return [[">=", m[1]], ["<", bump(p, i === -1 ? p.length - 1 : i)]];
  }
  if ((m = tok.match(/^~=(.+)$/))) {
    const p = nums(m[1]);
    return [[">=", m[1]], ["<", bump(p, Math.max(p.length - 2, 0))]];
  }
  if ((m = tok.match(/^~>?v?(.+)$/))) {
    const p = nums(m[1]);
    return [[">=", m[1]], ["<", bump(p, p.length > 1 ? 1 : 0)]];
  }
  if ((m = tok.match(/^(===|==|=|!=|>=|<=|>|<)?\s*v?(\d[\w.*+-]*)$/))) {
    const op = m[1] === "===" || m[1] === "=" ? "==" : m[1] ?? "";
    const ver = m[2];
    const wild = /(^|\.)[x*](\.|$)/i.test(ver);
    const p = nums(ver.split(/\.[x*]/i)[0]);
    // Bare partial ("20", "1.2", "1.2.x") or "==1.2.*" means "any version in that series".
    if ((op === "" && (wild || p.length < 3) && /^[\d.x*]+$/i.test(ver)) || (op === "==" && wild)) {
      return [[">=", p.join(".")], ["<", bump(p, p.length - 1)]];
    }
    if (op === "!=" && wild) return [];
    return [[op || "==", ver]];
  }
  return null; // git URLs, workspace:, file:, tags like "lts/*"
}

const test = (op, v, ref) => {
  const c = cmpVersion(v, ref);
  return { "==": c === 0, "!=": c !== 0, ">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0 }[op];
};

/** Does `version` satisfy the npm/PEP 440-style `spec`? Unknown syntax returns true (never rule out on a parse failure). */
export function satisfies(spec, version) {
  return String(spec ?? "")
    .split("||")
    .some((group) =>
      group
        .trim()
        .replace(/^(\S+)\s+-\s+(\S+)$/, ">=$1 <=$2") // npm hyphen range
        .replace(/([<>=!~^]+)\s+/g, "$1") // ">= 1.0" -> ">=1.0"
        .split(/[,\s]+/)
        .every((t) => {
          const cs = comparators(t);
          return cs === null || cs.every(([op, ref]) => test(op, version, ref));
        }),
    );
}

/** Could a loose spec (or a partial version like "20") resolve to an affected version? */
export function couldSatisfy(spec, a) {
  if (!a.versions?.length && !a.ranges?.length) return true;
  if ((a.versions ?? []).some((v) => satisfies(spec, v))) return true;
  // For ranges, test the lower bounds of both sides: two overlapping intervals share the larger lower bound.
  const bounds = String(spec ?? "")
    .split(/[\s,|]+/)
    .flatMap((t) => comparators(t) ?? [])
    .filter(([op]) => op !== "<" && op !== "<=" && op !== "!=")
    .map(([, v]) => v);
  return (a.ranges ?? []).some((r) => [r.introduced || "0", ...bounds].some((v) => satisfies(spec, v) && inRange(v, r)));
}

// Runtimes from version files are often partial ("20", "3.12" = any patch); managed engine versions reported by
// the cloud ("15.4") are exact.
function versionLevel(version, a, exact = /^v?\d+(\.\d+){2,}$/) {
  if (!version) return "likely";
  if (exact.test(version)) return affected(version, a) ? "direct" : "possible";
  return couldSatisfy(version, a) ? "likely" : "possible";
}

/**
 * How strongly does one inventory component match one incident `affects` entry?
 * Returns null (unrelated), or "direct" | "likely" | "possible". Broad by design (spec §12.2):
 * the same package at a safe version is still "possible" so the team runs the local check.
 */
// Engine names differ by source (RDS "postgres", Aurora "aurora-postgresql", a person typing "postgresql").
// Same family = versions are comparable. Related = a fork or compatible engine: matched, but versions aren't compared.
const ENGINE_ALIASES = { postgresql: "postgres", pg: "postgres", "aurora-postgresql": "postgres", "aurora-mysql": "mysql", mongo: "mongodb" };
const RELATED_ENGINES = { valkey: "redis", docdb: "mongodb", mariadb: "mysql" };
export const canonicalEngine = (e) => (e == null ? e : ENGINE_ALIASES[String(e).toLowerCase()] ?? String(e).toLowerCase());
const engineFamily = (e) => RELATED_ENGINES[canonicalEngine(e)] ?? canonicalEngine(e);

export function componentLevel(c, a) {
  if (a.kind === "cloud_resource") {
    // Engine-level incidents ("PostgreSQL 15.0-15.5") match any provider/service running that engine.
    const same = (x, y) => !x || String(x).toLowerCase() === String(y ?? "").toLowerCase();
    if (c.type !== "cloud_resource" || !same(a.provider, c.provider) || !same(a.service, c.service)) return null;
    if (a.engine && engineFamily(a.engine) !== engineFamily(c.engine)) return null;
    if (c.provenance?.source === "manual") return "manual_unverified";
    if (a.engine && canonicalEngine(a.engine) !== canonicalEngine(c.engine)) return "likely"; // related engine: versions not comparable
    return versionLevel(c.version, a, /^v?\d+(\.\d+)+$/);
  }
  if (matchKey(c) !== matchKey(a)) return null;
  switch (a.kind) {
    case "package":
      if (c.version) return affected(c.version, a) ? "direct" : "possible";
      return couldSatisfy(c.version_spec ?? "", a) ? "likely" : "possible";
    case "runtime":
      return versionLevel(c.version, a);
    case "container_image":
      if (!a.tags?.length && !a.digests?.length) return "likely";
      return a.tags?.includes(c.tag) || (c.digest && a.digests?.includes(c.digest)) ? "direct" : "possible";
    case "ci_action":
      // Advisories give version ranges; a tag like v4.2.1 compares, a major tag (v4) could be any 4.x, a SHA can't be compared.
      if (a.ranges?.length) return versionLevel(c.ref, a);
      return !a.refs?.length || a.refs.includes(c.ref) ? "direct" : "possible";
    case "service":
      return "likely";
  }
  return null;
}
