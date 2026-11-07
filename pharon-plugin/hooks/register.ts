import type { EngineInterface, Register } from 'claude-code'

/**
 * Pharon's warning light.
 *
 * Pharon's CLI already fetches, caches and de-duplicates this repo's open notices
 * (~/.pharon/notices/<key>.json). It writes that file at session start and never
 * again, so this mod asks it to refetch on a timer; the fetching stays the CLI's.
 */

const POLL_MS = 60_000
const REFETCH_MS = 10 * 60_000 // the CLI's own NOTICE_TTL_MS
const SEVERITY = ['critical', 'high', 'medium', 'low'] as const
type Severity = (typeof SEVERITY)[number]
type Notice = { id: string; kind: string; text: string }

/** Same rule as the CLI's normalizeRemote (lib/git.mjs); copied because that file imports node:child_process. */
export function normalizeRemote(url: string | undefined | null): string | null {
  if (!url) return null
  const u = url.trim().replace(/\.git\/?$/, '')
  const scp = u.match(/^(?:[^@/]+@)?([^:/]+):(?!\/\/)(.+)$/) // git@github.com:acme/api
  if (scp && !/^[a-z+]+:\/\//i.test(u)) return `${scp[1]}/${scp[2]}`.toLowerCase().replace(/\/+$/, '')
  try {
    const p = new URL(u)
    return `${p.hostname}${p.pathname}`.toLowerCase().replace(/\/+$/, '')
  } catch {
    return null
  }
}

// shortcut: severity is read out of the notice text, which /v1/notices builds from a fixed
// template ("<id> (<severity>): …"). Upgrade when that route carries `severity` as its own field.
export function severityOf(n: Notice): Severity | null {
  return (n.text.match(/\((critical|high|medium|low)\)/)?.[1] as Severity | undefined) ?? null
}

export function statusLine(notices: Notice[]): string | undefined {
  if (!notices.length) return undefined
  const worst = SEVERITY.find(s => notices.some(n => severityOf(n) === s))
  return worst ? `🔦 ${worst} · ${notices.length} open` : `🔦 ${notices.length} to check`
}

/** Cache file for the repo at `cwd`, keyed exactly as the CLI keys it, or null when there is no repo. */
export function cacheKey(remoteUrl: string | null, root: string | null): string | null {
  const key = normalizeRemote(remoteUrl) ?? (root ? `path:${root}` : null)
  return key ? `notices/${key.replace(/[^\w.-]+/g, '_')}.json` : null
}

/** Notices worth interrupting for, that this session has not already shown. `seen` null = first read, so nothing. */
export function newUrgent(notices: Notice[], seen: Set<string> | null): Notice[] {
  if (!seen) return []
  return notices.filter(n => !seen.has(n.id) && (severityOf(n) === 'critical' || severityOf(n) === 'high'))
}

let cachePath: string | null = null
let repoCwd = '.'
let seen: Set<string> | null = null // null until the first read, so a session never opens with a burst of toasts

async function run($: EngineInterface, argv: string[], cwd: string): Promise<string | null> {
  try {
    const r = await $.process.run(argv, { cwd })
    return r.exitCode === 0 ? r.stdout.trim() : null
  } catch {
    return null
  }
}

async function findCache($: EngineInterface, cwd: string): Promise<string | null> {
  const home = (await $.env.get('PHARON_HOME')) ?? `${await $.env.get('HOME')}/.pharon`
  const remote = await run($, ['git', 'config', '--get', 'remote.origin.url'], cwd)
  const root = remote ? null : await run($, ['git', 'rev-parse', '--show-toplevel'], cwd)
  const rel = cacheKey(remote, root)
  return rel ? `${home}/${rel}` : null
}

/** Ask the CLI to refetch this repo's notices into the cache. Fetching stays the CLI's job. */
async function refetch($: EngineInterface): Promise<void> {
  if (cachePath) await run($, [`${$.plugin.root}/bin/pharon`, 'notices'], repoCwd)
}

async function refresh($: EngineInterface): Promise<void> {
  if (!cachePath) return
  let notices: Notice[]
  try {
    notices = JSON.parse(await $.fs.read(cachePath))?.notices ?? []
  } catch {
    return // no cache yet (repo unlinked, or the first sync is still running): leave the line alone
  }
  $.ui.status(statusLine(notices))
  for (const n of newUrgent(notices, seen)) $.ui.toast(`🔦 Pharon: ${n.text}`, { timeoutMs: 12_000 })
  seen = new Set(notices.map(n => n.id))
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    cachePath = await findCache($, e.cwd)
    repoCwd = e.cwd
    await refresh($)
    $.clock.every(POLL_MS, () => void refresh($))
    // The CLI writes the cache at session start and never again, so ask it to refetch.
    // First tick is one interval in, by which time its own SessionStart run has landed.
    $.clock.every(REFETCH_MS, () => void refetch($))
    return next(e)
  })
}
