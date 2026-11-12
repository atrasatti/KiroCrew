/**
 * The changes a pending update brings, as one short line each, for the
 * "What you'd get" list under About > Updates.
 *
 * The input is changelog markdown the update itself carries: the desktop feed's
 * `releaseNotes` (the target version's `CHANGELOG.md` section and the released
 * ones before it, written by `scripts/feed_release_notes.py` and cut down by
 * `notesSince`) or the lines a git checkout's check adds to
 * `CHANGELOG.md` (`/api/update/check`'s `changes`). Both follow the file's own
 * shape, so one reading serves both:
 *
 * - a top-level bullet is one change, named by its bold lead when it has one
 *   (`- **Live view**: ...` -> `Live view`);
 * - a paragraph that opens with a bold lead is one change
 *   (`**Chat and sessions.** ...` -> `Chat and sessions`), which is how the
 *   "Notable fixes" sections are written;
 * - a `###` section with neither is one change, named by its heading;
 * - version headings (`##`) and plain prose name nothing.
 */

const BULLET_RE = /^[-*+]\s+(.*)$/
const BOLD_LEAD_RE = /^\*\*(.+?)\*\*/
const H3_RE = /^###\s+(.*)$/

/** Markdown inline syntax removed, so a line reads as plain text. */
function plain(text: string): string {
  return text
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[*_`]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
}

/** A bold lead without the punctuation that ends it (`Live view:` -> `Live view`). */
function lead(text: string): string {
  return plain(text).replace(/[.:;,\s]+$/, '')
}

function entryOf(text: string): string {
  const bold = BOLD_LEAD_RE.exec(text)
  return bold ? lead(bold[1]) : plain(text)
}

export function changeEntries(markdown: string): string[] {
  const out: string[] = []
  let heading = ''
  let sectionHasItems = false
  let previousBlank = true
  const closeSection = () => {
    if (heading && !sectionHasItems) out.push(heading)
    heading = ''
    sectionHasItems = false
  }
  for (const raw of markdown.split(/\r?\n/)) {
    const line = raw.trimEnd()
    if (!line.trim()) {
      previousBlank = true
      continue
    }
    const startsParagraph = previousBlank
    previousBlank = false
    if (line.startsWith('## ') || line === '##') {
      closeSection()
      continue
    }
    const h3 = H3_RE.exec(line)
    if (h3) {
      closeSection()
      heading = plain(h3[1])
      continue
    }
    // Indented lines continue a bullet or nest under it: not changes of their own.
    if (/^\s/.test(line)) continue
    const bullet = BULLET_RE.exec(line)
    const text = bullet ? bullet[1] : startsParagraph && BOLD_LEAD_RE.test(line) ? line : null
    if (text === null) continue
    const entry = entryOf(text)
    if (!entry) continue
    out.push(entry)
    sectionHasItems = true
  }
  closeSection()
  return out
}

const SECTION_RE = /^##\s+\[([^\]]+)\]/

/** `0.12.0-rc.1` → `[0, 12, 0]`, plus whether a prerelease suffix follows. */
function releaseOf(version: string): { parts: number[]; pre: boolean } {
  const m = /^v?([0-9]+(?:\.[0-9]+)*)(.*)$/.exec(version.trim())
  if (!m) return { parts: [], pre: false }
  return { parts: m[1].split('.').map(Number), pre: m[2] !== '' && !m[2].startsWith('+') }
}

function compare(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0)
    if (d) return d
  }
  return 0
}

/**
 * The desktop feed's notes cut down to the releases the running build lacks.
 *
 * `scripts/feed_release_notes.py` writes the update's own section and the
 * released sections before it, each under its own `## [X.Y.Z]` heading. Keeps the
 * sections newer than `runningVersion`, and the running release's own section
 * when the running build is a prerelease of it. Notes with no such heading come
 * from a feed that predates the format: they are one release's section, returned
 * whole and not described as a range.
 */
export function notesSince(notes: string, runningVersion: string): { notes: string; sinceBuild: boolean } {
  const lines = notes.split(/\r?\n/)
  if (!lines.some(line => SECTION_RE.test(line))) return { notes, sinceBuild: false }
  const running = releaseOf(runningVersion)
  const kept: string[] = []
  let keep = false
  for (const line of lines) {
    const heading = SECTION_RE.exec(line)
    if (heading) {
      const order = compare(releaseOf(heading[1]).parts, running.parts)
      keep = running.parts.length === 0 || order > 0 || (order === 0 && running.pre)
    }
    if (keep) kept.push(line)
  }
  return { notes: kept.join('\n').trim(), sinceBuild: true }
}

/** The `/api/releases` fields `archiveNotes` reads. */
export interface ArchiveRelease { version: string; date: string; body: string; is_current: boolean }

/**
 * The update's changes from this install's own release list, for an update that
 * carries no notes: the sections newer than the running release, up to and
 * including `target`, newest first. Empty when the list has none of them, which
 * is the usual case: the bundled `CHANGELOG.md` stops at the running build.
 */
export function archiveNotes(releases: ArchiveRelease[] | undefined, target: string): string {
  if (!releases?.length) return ''
  const current = releases.findIndex(r => r.is_current)
  if (current <= 0) return ''
  const goal = releaseOf(target).parts
  return releases
    .slice(0, current)
    .filter(r => r.body && (goal.length === 0 || compare(releaseOf(r.version).parts, goal) <= 0))
    // Rebuilt in CHANGELOG.md's own heading shape, which `changeEntries` and
    // `notesSince` read: markup, not copy.
    .map(r => [['##', `[${r.version}]`, ...(r.date ? ['-', r.date] : [])].join(' '), r.body].join('\n\n'))
    .join('\n\n')
}
