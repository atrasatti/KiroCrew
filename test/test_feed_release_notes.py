"""A desktop channel file's ``releaseNotes`` is the published version's CHANGELOG.md sections."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
import yaml

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "feed_release_notes.py"

_SECTION = '### Fixed\n- version: 9.9.9 is "quoted" \\ — and: colons'
_CHANGELOG = f"""# Changelog

## [0.4.0] — 2026-08-25

{_SECTION}

## [0.3.0] — 2026-08-17

- older
"""


@pytest.fixture(scope="module")
def notes() -> ModuleType:
    spec = importlib.util.spec_from_file_location("feed_release_notes", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_OLDER = "## [0.3.0] - 2026-08-17\n\n- older"
_BOTH = f"## [0.4.0] - 2026-08-25\n\n{_SECTION}\n\n{_OLDER}"


@pytest.mark.parametrize("version", ["0.4.0", "0.4.0-insider.14", "0.4.0-rc.2"])
def test_a_release_and_its_prereleases_get_its_section_then_the_older_ones(notes: ModuleType, version: str) -> None:
    assert notes.release_notes(_CHANGELOG, version) == _BOTH


def test_an_older_release_leaves_out_the_newer_sections(notes: ModuleType) -> None:
    assert notes.release_notes(_CHANGELOG, "0.3.0") == _OLDER


@pytest.mark.parametrize("version", ["0.5.0-nightly.20261105t010203", "0.5.0"])
def test_a_version_with_no_section_starts_at_the_newest_released_one(notes: ModuleType, version: str) -> None:
    assert notes.release_notes(_CHANGELOG, version) == _BOTH


def test_no_version_gets_empty_notes(notes: ModuleType) -> None:
    assert notes.release_notes(_CHANGELOG, "") == ""


def test_the_sections_are_capped(notes: ModuleType) -> None:
    many = "".join(f"## [0.{n}.0] - 2026-01-01\n\n- change {n}\n\n" for n in range(30, 0, -1))
    out = notes.release_notes(many, "0.30.0")
    assert out.count("## [") == notes.MAX_SECTIONS
    assert out.startswith("## [0.30.0]")


def test_printed_notes_are_one_yaml_value_in_the_channel_file(
    notes: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "CHANGELOG.md").write_text(_CHANGELOG, encoding="utf-8")
    monkeypatch.setattr(notes, "ROOT", tmp_path)
    assert notes.main(["feed_release_notes.py", "0.4.0-insider.14"]) == 0
    printed = capsys.readouterr().out
    assert printed.isascii() and printed.count("\n") == 1
    feed = yaml.safe_load(f"version: 0.4.0-insider.14\nreleaseNotes: {printed}")
    assert feed == {"version": "0.4.0-insider.14", "releaseNotes": _BOTH}
