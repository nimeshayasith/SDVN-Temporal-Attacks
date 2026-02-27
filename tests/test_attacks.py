"""Tests for attack modules (replay, delay, timing)."""

from __future__ import annotations

import time
import uuid

import pytest

from src.network.vehicle import Message, Vehicle
from src.attacks.replay_attack import ReplayAttack
from src.attacks.delay_attack import DelayAttack
from src.attacks.timing_attack import TimingAttack


def _make_vehicle(vid: str = "v0") -> Vehicle:
    return Vehicle(vehicle_id=vid, position=(0.0, 0.0), speed=10.0, direction=0.0)


def _make_message(sender: str = "v0", receiver: str = "v1", seq: int = 1) -> Message:
    return Message(
        msg_id=str(uuid.uuid4()),
        sender_id=sender,
        receiver_id=receiver,
        data={"payload": "test"},
        timestamp=time.time(),
        sequence_number=seq,
    )


# ---------------------------------------------------------------------------
# Replay attack tests
# ---------------------------------------------------------------------------

class TestReplayAttack:
    def setup_method(self):
        self.attacker = ReplayAttack()

    def test_capture_stores_message(self):
        msg = _make_message()
        self.attacker.capture_message(msg)
        assert len(self.attacker.get_captured_messages()) == 1

    def test_captured_messages_are_copies(self):
        msg = _make_message()
        self.attacker.capture_message(msg)
        captured = self.attacker.get_captured_messages()[0]
        assert captured is not msg  # deep copy

    def test_replay_delivers_to_target(self):
        target = _make_vehicle("v1")
        msg = _make_message(receiver="v1")
        self.attacker.capture_message(msg)
        replayed = self.attacker.replay(target, delay=0.0)
        assert len(replayed) == 1
        assert len(target._inbox) == 1

    def test_replay_with_modified_timestamp(self):
        target = _make_vehicle("v1")
        old_ts = time.time() - 100
        msg = _make_message()
        msg.timestamp = old_ts
        self.attacker.capture_message(msg)
        replayed = self.attacker.replay(target, modify_timestamp=True)
        assert replayed[0].timestamp > old_ts

    def test_replay_preserves_original_timestamp(self):
        target = _make_vehicle("v1")
        old_ts = time.time() - 100
        msg = _make_message()
        msg.timestamp = old_ts
        self.attacker.capture_message(msg)
        replayed = self.attacker.replay(target, modify_timestamp=False)
        assert abs(replayed[0].timestamp - old_ts) < 0.001

    def test_clear_empties_capture_buffer(self):
        self.attacker.capture_message(_make_message())
        self.attacker.clear()
        assert self.attacker.get_captured_messages() == []


# ---------------------------------------------------------------------------
# Delay attack tests
# ---------------------------------------------------------------------------

class TestDelayAttack:
    def setup_method(self):
        self.attacker = DelayAttack()

    def test_intercept_returns_copy(self):
        msg = _make_message()
        held = self.attacker.intercept(msg)
        assert held is not msg

    def test_intercept_queues_message(self):
        msg = _make_message()
        self.attacker.intercept(msg)
        assert len(self.attacker._queue) == 1

    def test_inject_delayed_delivers_to_target(self):
        target = _make_vehicle("v1")
        msg = _make_message()
        self.attacker.inject_delayed(msg, delay_seconds=0.0, target_node=target)
        assert len(target._inbox) == 1

    def test_inject_delayed_preserves_timestamp(self):
        original_ts = time.time() - 5
        msg = _make_message()
        msg.timestamp = original_ts
        result = self.attacker.inject_delayed(msg, delay_seconds=0.0)
        assert abs(result.timestamp - original_ts) < 0.001

    def test_simulate_delay_attack(self):
        src = _make_vehicle("src")
        dst = _make_vehicle("dst")
        delayed = self.attacker.simulate_delay_attack(
            vehicles=[src, dst],
            source_id="src",
            destination_id="dst",
            delay_range=(0.0, 0.0),
            num_messages=3,
        )
        assert len(delayed) == 3
        assert len(dst._inbox) == 3

    def test_simulate_with_missing_nodes(self):
        src = _make_vehicle("src")
        result = self.attacker.simulate_delay_attack(
            vehicles=[src],
            source_id="src",
            destination_id="ghost",
        )
        assert result == []


# ---------------------------------------------------------------------------
# Timing attack tests
# ---------------------------------------------------------------------------

class TestTimingAttack:
    def setup_method(self):
        self.attacker = TimingAttack()

    def test_observe_timing_populates_observations(self):
        msgs = [_make_message(seq=i + 1) for i in range(5)]
        self.attacker.observe_timing(msgs)
        assert len(self.attacker._observations) == 5

    def test_analyze_pattern_empty_returns_empty(self):
        result = self.attacker.analyze_pattern()
        assert result == {}

    def test_analyze_pattern_returns_stats(self):
        msgs = [_make_message(seq=i + 1) for i in range(5)]
        # Space timestamps artificially
        for i, m in enumerate(msgs):
            m.timestamp = time.time() + i * 0.1
        self.attacker.observe_timing(msgs)
        pattern = self.attacker.analyze_pattern()
        assert "mean_inter_arrival" in pattern
        assert "std_inter_arrival" in pattern
        assert pattern["observation_count"] == 5

    def test_estimate_route_returns_list(self):
        msgs = [
            _make_message(sender=f"v{i}", seq=i + 1) for i in range(3)
        ]
        for i, m in enumerate(msgs):
            m.timestamp = time.time() + i * 0.05
        self.attacker.observe_timing(msgs)
        route = self.attacker.estimate_route()
        assert isinstance(route, list)
        assert len(route) > 0

    def test_clear_resets_observations(self):
        self.attacker.observe_timing([_make_message()])
        self.attacker.clear()
        assert self.attacker._observations == []
