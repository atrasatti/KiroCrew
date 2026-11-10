"""Bounded accounting for connected-computer replies larger than the tracking limit."""

from __future__ import annotations

import json

import pytest

from kiro_crew.connected_computers import launch
from kiro_crew.connected_computers.launch import PendingCalls


def _call(rid: int | str) -> bytes:
    return (json.dumps({"id": rid, "method": "tools/call"}) + "\n").encode("utf-8")


def _feed(pending: PendingCalls, data: bytes, chunk_size: int) -> None:
    for start in range(0, len(data), chunk_size):
        pending.observe_response(data[start : start + chunk_size])
        if pending._down_skip:
            assert len(pending._down_head) <= launch._MAX_RESPONSE_PREFIX
        else:
            assert len(pending._down_head) <= launch._MAX_TRACKED_LINE


@pytest.fixture
def small_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(launch, "_MAX_TRACKED_LINE", 256)
    monkeypatch.setattr(launch, "_MAX_RESPONSE_PREFIX", 96)


def test_a_reply_over_the_real_limit_releases_only_its_slot() -> None:
    pending = PendingCalls()
    for rid in (7, 8):
        assert pending.admit(_call(rid)) == (_call(rid), b"")
    pending.observe_response(b'{"jsonrpc":"2.0","id":7,"result":{"data":"')
    chunk = b"x" * (32 * 1024)
    for _ in range(launch._MAX_TRACKED_LINE // len(chunk) + 1):
        _feed(pending, chunk, len(chunk))
    assert pending._down_skip
    assert len(pending._down_head) == launch._MAX_RESPONSE_PREFIX
    assert len(pending) == 2, "the slot stays occupied until the reply's newline"
    pending.observe_response(b'"}}\n')
    assert len(pending) == 1
    assert json.loads(pending.close_out("unknown"))["id"] == 8


@pytest.mark.parametrize("chunk_size", [1, 31, 1024])
@pytest.mark.parametrize("rid", [7, "7", 'quoted-"\\-\u00e9'])
def test_oversized_replies_release_slots_across_chunk_boundaries(
    small_bounds: None, chunk_size: int, rid: int | str
) -> None:
    pending = PendingCalls()
    assert pending.admit(_call(rid)) == (_call(rid), b"")
    reply = (json.dumps({"id": rid, "result": "x" * 512}) + "\n").encode("utf-8")
    _feed(pending, reply, chunk_size)
    assert len(pending) == 0
    assert not pending.mid_response
    assert pending.close_out("unknown") == b""


def test_65_sequential_oversized_replies_do_not_exhaust_admission(small_bounds: None) -> None:
    pending = PendingCalls()
    for rid in range(65):
        call = _call(rid)
        assert pending.admit(call) == (call, b""), f"call {rid} must not be refused"
        reply = (json.dumps({"id": rid, "result": "x" * 512}) + "\n").encode("utf-8")
        _feed(pending, reply, 31)
    assert len(pending) == 0
    assert pending.close_out("unknown") == b""


def test_an_id_beyond_the_prefix_stays_pending_until_close(small_bounds: None) -> None:
    pending = PendingCalls()
    for rid in (8, 7):
        assert pending.admit(_call(rid)) == (_call(rid), b"")
    reply = (json.dumps({"result": "x" * 512, "id": 7}) + "\n").encode("utf-8")
    _feed(pending, reply, 31)
    assert len(pending) == 2, "neither the oldest call nor an unobserved id may be guessed"
    pending.observe_response(b'{"id":8,"result":{}}\n')
    assert len(pending) == 1
    unknown = json.loads(pending.close_out(launch.ended_message("Laptop")))
    assert unknown["id"] == 7
    assert unknown["result"]["isError"] is True
    assert "unknown" in unknown["result"]["content"][0]["text"]
    assert "not retried" in unknown["result"]["content"][0]["text"]
    assert len(pending) == 0


def test_a_half_delivered_oversized_reply_still_gets_an_unknown_outcome(
    small_bounds: None,
) -> None:
    pending = PendingCalls()
    assert pending.admit(_call(7)) == (_call(7), b"")
    _feed(pending, b'{"id":7,"result":"' + b"x" * 512, 31)
    assert pending.mid_response
    assert len(pending) == 1
    unknown = pending.close_out("unknown")
    assert unknown.startswith(b"\n")
    assert json.loads(unknown)["id"] == 7
    assert not pending.mid_response
    assert not pending._down_head
    assert not pending._down_skip


def test_oversized_then_small_reply_in_one_read_resets_the_prefix(small_bounds: None) -> None:
    pending = PendingCalls()
    for rid in (7, 8):
        assert pending.admit(_call(rid)) == (_call(rid), b"")
    pending.observe_response(b'{"id":7,"result":"' + b"x" * 512 + b'"}\n{"id":8,"result":{}}\n')
    assert len(pending) == 0
    assert not pending._down_head
    assert not pending._down_skip


@pytest.mark.parametrize(
    ("prefix", "expected"),
    [
        (b'{"id":7,"result":"unfinished', "7"),
        (b'{"result":{},"id":"7",', '"7"'),
        (b' { "id" : 7 , "result" : "unfinished', "7"),
        (b'{"meta":{"id":8},"id":7,"result":"unfinished', "7"),
        (b'{"meta":"\\"id\\":8","id":7,"result":"unfinished', "7"),
        (b'{"result":{"id":7,"data":"unfinished', None),
        (b'{"result":"\\"id\\":7 unfinished', None),
        (b'{"method":"server/request","id":7,"params":"unfinished', None),
        (b'{"id":7,"method":"server/request","params":"unfinished', None),
        (b'{"id":7', None),
        (b'{"id":7e', None),
        (b'{"id":"unfinished', None),
        (b'{"\\u0069d":7,"result":"unfinished', "7"),
        (b'{"id":7,"result":"utf8-\xc3', "7"),
        (b'[{"id":7,"result":"unfinished', None),
    ],
)
def test_prefix_matching_uses_complete_top_level_fields(
    prefix: bytes, expected: str | None
) -> None:
    assert launch._response_key_from_prefix(prefix) == expected
