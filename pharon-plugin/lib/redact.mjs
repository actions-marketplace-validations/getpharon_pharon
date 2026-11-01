// Redaction rules (spec §18.4), shared by the CLI (before upload) and the server (on ingest, as a second line).
import { createHash } from "node:crypto";
import { globMatch } from "./match.mjs";

export const validPattern = (p) => typeof p === "string" && /^[\w@./*:+-]{1,200}$/.test(p);

/**
 * Versions and specs are uploaded, and URL-style specs can carry credentials (git+https://TOKEN@host/...).
 * Keep version-like text only; anything else becomes "<scheme>:(redacted)".
 */
export function safeSpec(spec) {
  if (spec == null) return spec;
  const s = String(spec).trim();
  if (/^[\w.<>=!~^*|, +-]{0,120}$/.test(s)) return s;
  return `${s.match(/^([a-z][a-z0-9+.-]*):/i)?.[1].toLowerCase() ?? "other"}:(redacted)`;
}
const bare = (location) => location.replace(/(:\d+|#.*)$/, ""); // "Dockerfile:3" -> "Dockerfile"

/**
 * A rule's glob matches a component's name (vendor for services) or one of its file paths.
 * "drop" removes the component. "hash" replaces a matching name with a salted hash and hides matching paths.
 */
export function redact(components, rules, salt = "") {
  const rs = (rules ?? []).filter((r) => validPattern(r.pattern)).map((r) => ({ hash: r.action === "hash", pattern: r.pattern }));
  if (!rs.length) return components;
  const hits = (s) => rs.filter((r) => globMatch(r.pattern, s));
  // Evidence like "package:boto3" or "file:deploy/x.yml" can name a redacted thing too.
  const scrub = (evidence) =>
    evidence?.flatMap((e) => {
      const rules = hits(bare(e.slice(e.indexOf(":") + 1)));
      if (!rules.length) return [e];
      return rules.some((r) => !r.hash) ? [] : [`${e.slice(0, e.indexOf(":"))}:redacted`];
    });
  const out = [];
  for (const c of components) {
    const field = c.type === "service" ? "vendor" : "name";
    const nameRules = hits(String(c[field]));
    const pathRules = (c.locations ?? []).flatMap((l) => hits(bare(l)));
    const all = [...nameRules, ...pathRules];
    if (all.some((r) => !r.hash)) continue; // any "drop" wins
    const evidence = scrub(c.evidence);
    if (!all.length && evidence?.join() === c.evidence?.join()) {
      out.push(c);
      continue;
    }
    const r = { ...c, locations: (c.locations ?? []).map((l) => (hits(bare(l)).length ? "redacted" : l)), ...(evidence && { evidence }) };
    if (nameRules.length) {
      r[field] = `redacted-${createHash("sha256").update(salt + c[field]).digest("hex").slice(0, 12)}`;
      delete r.purl;
      delete r.evidence;
    }
    if (!c.locations) delete r.locations;
    out.push(r);
  }
  return out;
}
