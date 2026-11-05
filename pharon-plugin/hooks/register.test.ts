import { expect, test } from 'claude-code/testing'
import type { On } from 'claude-code'
import { cacheKey, newUrgent, severityOf, statusLine } from './register'

// Two real notices from this machine's cache, verbatim.
const HIGH = {
  id: 'incident:nodejs-brotli-decoder-rce-2026-10:likely',
  kind: 'incident',
  text: 'nodejs-brotli-decoder-rce-2026-10 (high): Node.js native Brotli decoder RCE and memory disclosure (CVE-2026-111497). Likely affected. Run /pharon:check-incident nodejs-brotli-decoder-rce-2026-10',
}
const MEDIUM = {
  id: 'incident:google-cloud-sdk-emudhra-ca-trust-2026-11:likely',
  kind: 'incident',
  text: 'google-cloud-sdk-emudhra-ca-trust-2026-11 (medium): Compromised eMudhra CA keys: certifi, grpc, httplib2, google-api-client and runtimes need trust store updates. Likely affected. Run /pharon:check-incident google-cloud-sdk-emudhra-ca-trust-2026-11',
}
const GAP = { id: 'gaps:aws-1', kind: 'gaps', text: "Pharon can't fully see part of this stack (aws). Run /pharon:setup to choose how to track it." }

test('the cache key matches the file the CLI actually wrote', () => {
  // ~/.pharon/notices/github.com_acme_api.json, from git@github.com:acme/api.git
  expect(cacheKey('git@github.com:acme/api.git', null)).toBe('notices/github.com_acme_api.json')
  expect(cacheKey('https://github.com/acme/api.git', null)).toBe('notices/github.com_acme_api.json')
  expect(cacheKey(null, '/Users/me/scratch')).toBe('notices/path_Users_me_scratch.json') // no remote: the CLI's fallback
  expect(cacheKey(null, null)).toBe(null)
})

test('severity comes out of the server-built text', () => {
  expect(severityOf(HIGH)).toBe('high')
  expect(severityOf(MEDIUM)).toBe('medium')
  expect(severityOf(GAP)).toBe(null) // gaps and confirmations carry no severity
})

test('the line shows the worst severity and the total', () => {
  expect(statusLine([])).toBe(undefined) // nothing open clears the line
  expect(statusLine([HIGH, MEDIUM])).toBe('🔦 high · 2 open')
  expect(statusLine([MEDIUM, HIGH])).toBe('🔦 high · 2 open') // order of the cache must not matter
  expect(statusLine([GAP])).toBe('🔦 1 to check')
  expect(statusLine([GAP, MEDIUM])).toBe('🔦 medium · 2 open')
})

/** Drives the real hook: git + env + the cache file are answered as the engine would. */
function engine(on: On, notices: unknown[] | null, status: (t?: string) => void, toast: (t: string) => void) {
  on('process.run', (_: unknown, e: { argv: readonly string[] }) => ({
    value: { exitCode: 0, stdout: e.argv.includes('--get') ? 'git@github.com:acme/api.git\n' : '/repo\n', stderr: '', isStdoutTruncated: false, isStderrTruncated: false },
  }))
  on('env.get', (_: unknown, e: { name: string }) => ({ value: e.name === 'HOME' ? '/Users/me' : undefined }))
  on('fs.read', () => {
    if (notices === null) throw new Error('ENOENT') // repo not linked yet
    return { value: JSON.stringify({ fetched_at: 1, notices }) }
  })
  on('clock.every', () => ({ value: undefined }))
  on('ui.status', (_: unknown, e: { text?: string }) => { status(e.text); return { value: undefined } })
  on('ui.toast', (_: unknown, e: { text: string }) => { toast(e.text); return { value: undefined } })
  on('session.start', (_: unknown, e: { cwd: string }) => ({ cwd: e.cwd }))
}

test('session start sets the line from the cache and toasts nothing', async ($, on) => {
  let line: string | undefined = 'untouched'
  const toasts: string[] = []
  engine(on, [HIGH, MEDIUM], t => (line = t), t => toasts.push(t))

  await $.session.start({ cwd: '/repo', surface: 'terminal', isInteractive: true })

  expect(line).toBe('🔦 high · 2 open')
  expect(toasts.length).toBe(0) // the first read is the baseline: opening a session must not burst toasts
})

test('an unreadable cache leaves the line alone', async ($, on) => {
  let line: string | undefined = 'untouched'
  engine(on, null, t => (line = t), () => {})

  await $.session.start({ cwd: '/repo', surface: 'terminal', isInteractive: true })

  expect(line).toBe('untouched')
})

test('only new critical or high notices interrupt', () => {
  const ids = (ns: { id: string }[]) => ns.map(n => n.id)

  expect(newUrgent([HIGH, MEDIUM], null)).toEqual([]) // first read is the baseline: a session never opens with a burst
  expect(ids(newUrgent([MEDIUM, HIGH], new Set([MEDIUM.id])))).toEqual([HIGH.id]) // the new high interrupts
  expect(newUrgent([MEDIUM, HIGH], new Set([MEDIUM.id, HIGH.id]))).toEqual([]) // already shown: stays quiet
  expect(newUrgent([MEDIUM], new Set())).toEqual([]) // medium is never worth a toast
  expect(newUrgent([GAP], new Set())).toEqual([]) // nor is a gap, which carries no severity
})
