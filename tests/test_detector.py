"""Tests for the temporal attack detector."""

from __future__ import annotations

import time
import uuid

import pytest

from src.network.vehicle import Message
from src.detection.detector import DetectionResult, TemporalAttackDetector


def _make_message(
    sender: str = "v0",
    receiver: str = "v1",
    seq: int = 1,
    timestamp_offset: float = 0.0,
    msg_id: str | None = None,
) -> Message:
    return Message(
        msg_id=msg_id or str(uuid.uuid4()),
        sender_id=sender,
        receiver_id=receiver,
        data={"payload": "test"},
        timestamp=time.time() + timestamp_offset,
        sequence_number=seq,
    )


class TestTimestampValidation:
    def setup_method(self):
        self.detector = TemporalAttackDetector()

    def test_fresh_message_is_valid(self):
        msg = _make_message()
        result = self.detector.timestamp_validation(msg, window=5.0)
        assert result.is_attack is False

    def test_stale_message_flagged(self):
        msg = _make_message(timestamp_offset=-10.0)
        result = self.detector.timestamp_validation(msg, window=5.0)
        assert result.is_attack is True
        assert result.attack_type == "timestamp_anomaly"
        assert result.details["reason"] == "stale_timestamp"

    def test_future_timestamp_flagged(self):
        msg = _make_message(timestamp_offset=100.0)
        result = self.detector.timestamp_validation(msg, window=5.0)
        assert result.is_attack is True
        assert result.details["reason"] == "future_timestamp"


class TestSequenceNumberCheck:
    def setup_method(self):
        self.detector = TemporalAttackDetector()

    def test_correct_sequence_passes(self):
        msg = _make_message(seq=5)
        result = self.detector.sequence_number_check(msg, expected_seq=5)
        assert result.is_attack is False

    def test_low_sequence_detected_as_replay(self):
        msg = _make_message(seq=3)
        result = self.detector.sequence_number_check(msg, expected_seq=10)
        assert result.is_attack is True
        assert result.attack_type == "replay_attack"

    def test_large_gap_detected(self):
        msg = _make_message(seq=200)
        result = self.detector.sequence_number_check(msg, expected_seq=5)
        assert result.is_attack is True
        assert result.attack_type == "sequence_gap"


class TestDetectReplay:
    def setup_method(self):
        self.detector = TemporalAttackDetector()

    def test_new_message_passes(self):
        msg = _make_message()
        result = self.detector.detect_replay(msg, [])
        assert result.is_attack is False

    def test_duplicate_msg_id_flagged(self):
        fixed_id = str(uuid.uuid4())
        original = _make_message(msg_id=fixed_id)
        replay = _make_message(msg_id=fixed_id)
        result = self.detector.detect_replay(replay, [original])
        assert result.is_attack is True
        assert result.attack_type == "replay_attack"
        assert result.confidence >= 0.9


class TestDetectDelay:
    def setup_method(self):
        self.detector = TemporalAttackDetector()

    def test_timely_message_passes(self):
        msg = _make_message()
        result = self.detector.detect_delay(msg, max_delay_threshold=5.0)
        assert result.is_attack is False

    def test_delayed_message_flagged(self):
        msg = _make_message(timestamp_offset=-10.0)
        result = self.detector.detect_delay(msg, max_delay_threshold=2.0)
        assert result.is_attack is True
        assert result.attack_type == "delay_attack"


class TestAnalyzeMessage:
    def setup_method(self):
        self.detector = TemporalAttackDetector()

    def test_clean_message_no_attack(self):
        msg = _make_message(seq=1)
        result = self.detector.analyze_message(msg, context={"expected_seq": 1})
        assert result.is_attack is False

    def test_replayed_message_detected(self):
        fixed_id = str(uuid.uuid4())
        original = _make_message(msg_id=fixed_id)
        replay = _make_message(msg_id=fixed_id)
        result = self.detector.analyze_message(
            replay, context={"message_history": [original]}
        )
        assert result.is_attack is True
