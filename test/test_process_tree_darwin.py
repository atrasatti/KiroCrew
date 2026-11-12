"""On macOS the process-tree walk reads children and names in process, not through a spawn.

A session start walks its runtime's tree twice at spawn and twice more once the session's
MCP servers are up. With ``pgrep -P`` per process and ``ps -o comm=`` per name that was a
process start for each, one after the other, on the path the first prompt waits on. The
walk now asks ``platform_compat.darwin_child_pids`` and ``darwin_process_argv``, and keeps
``pgrep`` and ``ps`` for a host where those cannot answer. These tests hold which reader
answers, that a child which has ended is left out as ``pgrep`` left it out, that the name
is the bytes ``ps -o comm=`` gives (the last path part of ``argv[0]``), and that the
Linux and Windows paths never reach the macOS readers.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import kiro_crew.acp.runtime_process_tree as rpt
from kiro_crew.acp.client import _direct_children, _read_basename


def _never(*_args: Any, **_kwargs: Any) -> Any:
    pytest.fail("a macOS reader was asked off macOS, or a process was started")


def _platform(**readers: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "IS_WINDOWS": False,
        "trusted_system_bin": lambda _name: "/bin/ps",
        "darwin_child_pids": _never,
        "darwin_pid_is_zombie": lambda _pid: False,
        "darwin_process_argv": _never,
    }
    values.update(readers)
    return SimpleNamespace(**values)


def _spawner(out: bytes = b"") -> MagicMock:
    sub = MagicMock()
    sub.check_output.return_value = out
    return sub


def _on(platform: str, compat: SimpleNamespace, sub: MagicMock) -> Any:
    """The three facade bindings the walk reads, replaced together."""
    stack = patch.multiple(
        "kiro_crew.acp.client",
        sys=SimpleNamespace(platform=platform),
        platform_compat=compat,
        subprocess_mod=sub,
    )
    return stack


# ── children ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("children", [[4242, 4243], []])
def test_macos_children_come_from_libproc_without_a_spawn(children: list[int]) -> None:
    """An empty list is an answer too: a leaf costs no ``pgrep``."""
    sub = _spawner(b"999\n")
    asked: list[int] = []
    compat = _platform(darwin_child_pids=lambda pid: asked.append(pid) or list(children))
    with _on("darwin", compat, sub):
        assert _direct_children(100) == children
    assert asked == [100]
    sub.check_output.assert_not_called()


def test_a_macos_child_that_has_ended_is_left_out_as_pgrep_left_it_out() -> None:
    """libproc lists a child that ended and was not collected yet, or was collected a
    moment ago; ``pgrep -P`` lists neither, and the record is the set it always was."""
    sub = _spawner(b"999\n")
    ended = {4243: True, 4244: True}
    compat = _platform(
        darwin_child_pids=lambda _pid: [4242, 4243, 4244, 4245],
        darwin_pid_is_zombie=lambda pid: ended.get(pid, False),
    )
    with _on("darwin", compat, sub):
        assert _direct_children(100) == [4242, 4245]
    sub.check_output.assert_not_called()


def test_a_macos_child_whose_state_cannot_be_read_leaves_the_answer_to_pgrep() -> None:
    sub = _spawner(b"4242\n")
    compat = _platform(
        darwin_child_pids=lambda _pid: [4242, 4243],
        darwin_pid_is_zombie=lambda pid: None if pid == 4243 else False,
    )
    with _on("darwin", compat, sub):
        assert _direct_children(100) == [4242]
    assert sub.check_output.call_args[0][0] == ["pgrep", "-P", "100"]


def test_macos_falls_back_to_pgrep_when_libproc_cannot_be_asked() -> None:
    sub = _spawner(b"4242\n")
    with _on("darwin", _platform(darwin_child_pids=lambda _pid: None), sub):
        assert _direct_children(100) == [4242]
    assert sub.check_output.call_args[0][0] == ["pgrep", "-P", "100"]


def test_linux_children_never_reach_the_macos_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rpt, "_CHILDREN_INTERFACE", False)
    sub = _spawner(b"4242\n")
    with _on("linux", _platform(), sub):
        assert _direct_children(100) == [4242]


def test_windows_children_never_reach_the_macos_reader() -> None:
    sub = _spawner()
    with _on("win32", _platform(IS_WINDOWS=True), sub):
        assert _direct_children(100) == []
    sub.check_output.assert_not_called()


# ── names ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("argv", "name"),
    [
        (["/usr/local/bin/node", "/opt/tool/server.js"], b"node"),
        (["node"], b"node"),
        (["-zsh"], b"-zsh"),  # a login shell: ps prints argv[0], not the binary's path
        (["/Applications/Some App.app/Contents/MacOS/Some App", "--flag"], b"Some App"),
        (["  /usr/bin/python3  "], b"python3"),  # ps output is stripped the same way
    ],
)
def test_a_macos_name_is_the_last_path_part_of_argv0_without_a_spawn(
    argv: list[str], name: bytes
) -> None:
    sub = _spawner(b"/somewhere/else\n")
    with _on("darwin", _platform(darwin_process_argv=lambda _pid: list(argv)), sub):
        assert _read_basename(123) == name
    sub.check_output.assert_not_called()


@pytest.mark.parametrize(
    "argv",
    [
        None,  # the record cannot be read: another user's process, a zombie
        [],
        ["   "],  # an empty name is no name
        ["/opt/bin/caf\ufffd"],  # a byte the decode could not carry: only ps has it
    ],
)
def test_a_macos_name_the_record_cannot_give_comes_from_ps(argv: Any) -> None:
    sub = _spawner(b"/usr/local/bin/node\n")
    with _on("darwin", _platform(darwin_process_argv=lambda _pid: argv), sub):
        assert _read_basename(123) == b"node"
    assert sub.check_output.call_args[0][0] == ["/bin/ps", "-o", "comm=", "-p", "123"]


def test_a_windows_name_never_reaches_the_macos_reader() -> None:
    sub = _spawner()
    with _on("win32", _platform(IS_WINDOWS=True), sub):
        assert _read_basename(123) is None
    sub.check_output.assert_not_called()


def test_a_linux_name_never_reaches_the_macos_reader() -> None:
    proc = MagicMock()
    proc.exists.return_value = True
    proc.read_bytes.return_value = b"/usr/bin/node\x00server.js\x00"
    sub = _spawner()
    with _on("linux", _platform(), sub), patch("kiro_crew.acp.client.Path", return_value=proc):
        assert _read_basename(123) == b"node"
    sub.check_output.assert_not_called()
