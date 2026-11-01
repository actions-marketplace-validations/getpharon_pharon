import { execFileSync } from "node:child_process";

export function git(cwd, args, { raw = false } = {}) {
  try {
    const out = execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 256 * 1024 * 1024 });
    return raw ? out : out.trim();
  } catch {
    return null;
  }
}

/**
 * Normalize a git remote URL to a stable repo identity, e.g. github.com/acme/api.
 * Credentials embedded in the URL are dropped: they must never be uploaded.
 */
export function normalizeRemote(url) {
  if (!url) return null;
  let u = url.trim().replace(/\.git\/?$/, "");
  const scp = u.match(/^(?:[^@/]+@)?([^:/]+):(?!\/\/)(.+)$/); // git@github.com:acme/api
  if (scp && !/^[a-z+]+:\/\//i.test(u)) return `${scp[1]}/${scp[2]}`.toLowerCase().replace(/\/+$/, "");
  try {
    const p = new URL(u);
    return `${p.hostname}${p.pathname}`.toLowerCase().replace(/\/+$/, "");
  } catch {
    return null;
  }
}

/** Cheap repo facts used on the hook fast path (two git calls). */
export function repoBasics(cwd) {
  const out = git(cwd, ["rev-parse", "--show-toplevel", "--abbrev-ref", "HEAD"]);
  if (!out) return null;
  const [root, branch] = out.split("\n");
  const id = normalizeRemote(git(root, ["config", "--get", "remote.origin.url"]));
  return { root, branch: branch || "HEAD", id };
}

/** Slower facts, only computed when we actually build an inventory (background). */
export function repoDetails(root) {
  const sha = git(root, ["rev-parse", "HEAD"]);
  const head = git(root, ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"]);
  const defaultBranch =
    head?.replace(/^origin\//, "") ??
    ["main", "master"].find((b) => git(root, ["show-ref", "--verify", "--quiet", `refs/remotes/origin/${b}`]) !== null) ??
    "main";
  const hasRemote = !!git(root, ["remote"]);
  return {
    commit_sha: sha,
    commit_time: sha ? git(root, ["log", "-1", "--format=%cI"]) : null,
    default_branch: defaultBranch,
    // HEAD is pushed when no local commit is missing from every remote-tracking branch.
    pushed: !!sha && hasRemote && git(root, ["rev-list", "-n", "1", "HEAD", "--not", "--remotes"]) === "",
  };
}

/** Paths with uncommitted changes (staged, unstaged or untracked). */
export function changedPaths(root) {
  const out = git(root, ["status", "--porcelain", "-z", "--untracked-files=all"], { raw: true }); // leading space is significant
  if (out === null) return new Set();
  const paths = new Set();
  const parts = out.split("\0");
  for (let i = 0; i < parts.length; i++) {
    const entry = parts[i];
    if (entry.length < 4) continue;
    paths.add(entry.slice(3));
    if (entry[0] === "R" || entry[0] === "C") i++; // rename: next field is the old path
  }
  return paths;
}
