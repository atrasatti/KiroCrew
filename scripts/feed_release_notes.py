#!/usr/bin/env python3
"""Print a published version's ``CHANGELOG.md`` sections as the feed's ``releaseNotes``.

The desktop app shows a pending update's notes from the channel file's
``releaseNotes`` (``notesFrom`` in ``website/electron/runtime/update/feed-lane.js``),
and the publish lanes write that file by hand; this script supplies the field.

The notes are the published version's own section followed by the released
sections before it, newest first, each under its own ``## [X.Y.Z]`` heading. The
app keeps only the sections newer than the build it runs, so About > Updates can
list every change between that build and the update. The published version's
release is picked the way the release notes in Settings > About pick the
installed build's release (``changelog.build_release_list``): ``0.4.0-insider.14``
reads ``## [0.4.0]``, and a version with no section (a nightly) starts at the
newest released section below it.

Usage: feed_release_notes.py <version>   -> prints one JSON string

A JSON string is also a YAML double-quoted scalar, printed on one line in plain
ASCII: no changelog text can break the channel file, and no line of it can pass
for the top-level ``version:`` that ``check_feed_advance.py`` scans for.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Loaded by path: the publish jobs check the tree out without installing
# kiro_crew, and changelog.py imports only the standard library.
_spec = importlib.util.spec_from_file_location(
    "_kc_changelog", ROOT / "src" / "kiro_crew" / "changelog.py"
)
assert _spec and _spec.loader
changelog = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(changelog)


# shortcut: the feed carries at most this many sections, so a build further
# behind than that is shown only the newest ones (about 50 KB of JSON at
# 0.12.x); raise it if users skip more releases than that.
MAX_SECTIONS = 5


def release_notes(markdown: str, version: str) -> str:
    """*version*'s section and the released ones before it, or ``""`` when none exist."""
    releases = changelog.build_release_list(markdown, version)
    start = next((i for i, release in enumerate(releases) if release.is_current), len(releases))
    sections = []
    for release in releases[start:]:
        if not release.body:
            continue
        heading = f"## [{release.version}]" + (f" - {release.date}" if release.date else "")
        sections.append(f"{heading}\n\n{release.body}")
        if len(sections) == MAX_SECTIONS:
            break
    return "\n\n".join(sections)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: feed_release_notes.py <version>", file=sys.stderr)
        return 2
    markdown = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    print(json.dumps(release_notes(markdown, argv[1])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
