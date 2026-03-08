"""Detection module for temporal attacks in SDVN."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from src.network.vehicle import Message


@dataclass
class DetectionResult:
    """Result of a single message analysis.

    Attributes:
        is_attack: Whether an attack was detected.
        attack_type: Human-readable attack category or ``'none'``.
        confidence: Detection confidence in ``[0.0, 1.0]``.
        details: Free-form diagnostics dictionary.
    """

    is_attack: bool
    attack_type: str
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)


class TemporalAttackDetector:
    """Detects temporal attacks (replay, delay, timing) on SDVN messages.

    Each detection method is independent and returns a
    :class:`DetectionResult`.  The :meth:`analyze_message` method
    combines all checks into a single comprehensive verdict.
    """

    # Default validity window for fresh timestamps (seconds)
    DEFAULT_TIMESTAMP_WINDOW: float = 5.0
    # Default maximum acceptable message delay (seconds)
    DEFAULT_MAX_DELAY: float = 2.0

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def timestamp_validation(
        self,
        message: Message,
        window: float = DEFAULT_TIMESTAMP_WINDOW,
    ) -> DetectionResult:
        """Validate that *message*.timestamp is within the acceptable window.

        A message whose timestamp is older than *window* seconds – or is
        set in the future – is flagged as suspicious.

        Args:
            message: The message to validate.
            window: Maximum acceptable age in seconds.

        Returns:
            :class:`DetectionResult` with ``attack_type='timestamp_anomaly'``
            if out of range.
        """
        now = time.time()
        age = now - message.timestamp
        if age < 0:
            return DetectionResult(
                is_attack=True,
                attack_type="timestamp_anomaly",
                confidence=0.9,
                details={"reason": "future_timestamp", "age_seconds": age},
            )
        if age > window:
            confidence = min(1.0, age / (window * 2))
            return DetectionResult(
                is_attack=True,
                attack_type="timestamp_anomaly",
                confidence=confidence,
                details={"reason": "stale_timestamp", "age_seconds": age, "window": window},
            )
        return DetectionResult(
            is_attack=False,
            attack_type="none",
            confidence=1.0 - age / window,
            details={"age_seconds": age},
        )

    def sequence_number_check(
        self,
        message: Message,
        expected_seq: int,
    ) -> DetectionResult:
        """Verify that *message*.sequence_number matches *expected_seq*.

        A sequence number lower than expected indicates a replay; a gap
        suggests packet loss or reordering.

        Args:
            message: The incoming message.
            expected_seq: The next expected sequence number.

        Returns:
            :class:`DetectionResult` with appropriate ``attack_type``.
        """
        seq = message.sequence_number
        if seq < expected_seq:
            return DetectionResult(
                is_attack=True,
                attack_type="replay_attack",
                confidence=0.85,
                details={
                    "reason": "sequence_number_too_low",
                    "received": seq,
                    "expected": expected_seq,
                },
            )
        if seq > expected_seq + 10:
            return DetectionResult(
                is_attack=True,
                attack_type="sequence_gap",
                confidence=0.6,
                details={
                    "reason": "large_sequence_gap",
                    "received": seq,
                    "expected": expected_seq,
                },
            )
        return DetectionResult(
            is_attack=False,
            attack_type="none",
            confidence=1.0,
            details={"sequence_number": seq},
        )

    def detect_replay(
        self,
        message: Message,
        message_history: List[Message],
    ) -> DetectionResult:
        """Check whether *message* is a replay of a previously seen message.

        A replay is identified by a duplicate ``msg_id`` in *message_history*.

        Args:
            message: The candidate message.
            message_history: Previously processed messages.

        Returns:
            :class:`DetectionResult` flagged if a duplicate is found.
        """
        seen_ids: Set[str] = {m.msg_id for m in message_history}
        if message.msg_id in seen_ids:
            return DetectionResult(
                is_attack=True,
                attack_type="replay_attack",
                confidence=0.95,
                details={"reason": "duplicate_msg_id", "msg_id": message.msg_id},
            )
        return DetectionResult(
            is_attack=False,
            attack_type="none",
            confidence=1.0,
            details={"msg_id": message.msg_id},
        )

    def detect_delay(
        self,
        message: Message,
        max_delay_threshold: float = DEFAULT_MAX_DELAY,
    ) -> DetectionResult:
        """Detect whether *message* has been excessively delayed in transit.

        Args:
            message: The message to inspect.
            max_delay_threshold: Maximum acceptable end-to-end delay in
                seconds.

        Returns:
            :class:`DetectionResult` flagged if the message is too old.
        """
        delay = time.time() - message.timestamp
        if delay > max_delay_threshold:
            confidence = min(1.0, delay / (max_delay_threshold * 3))
            return DetectionResult(
                is_attack=True,
                attack_type="delay_attack",
                confidence=confidence,
                details={
                    "reason": "excessive_delay",
                    "delay_seconds": delay,
                    "threshold": max_delay_threshold,
                },
            )
        return DetectionResult(
            is_attack=False,
            attack_type="none",
            confidence=1.0 - delay / max_delay_threshold,
            details={"delay_seconds": delay},
        )

    # ------------------------------------------------------------------
    # Comprehensive analysis
    # ------------------------------------------------------------------

    def analyze_message(
        self,
        message: Message,
        context: Optional[Dict[str, Any]] = None,
    ) -> DetectionResult:
        """Run all detection checks and return the most severe result.

        Args:
            message: The message to analyse.
            context: Optional dictionary that may contain:
                - ``message_history`` (:class:`list`) – prior messages
                - ``expected_seq`` (:class:`int`) – next expected seq no.
                - ``max_delay`` (:class:`float`) – delay threshold
                - ``timestamp_window`` (:class:`float`) – freshness window

        Returns:
            The most confident attack :class:`DetectionResult`, or a
            benign result if no attack is detected.
        """
        if context is None:
            context = {}

        history: List[Message] = context.get("message_history", [])
        expected_seq: int = context.get("expected_seq", message.sequence_number)
        max_delay: float = context.get("max_delay", self.DEFAULT_MAX_DELAY)
        ts_window: float = context.get("timestamp_window", self.DEFAULT_TIMESTAMP_WINDOW)

        results = [
            self.timestamp_validation(message, window=ts_window),
            self.sequence_number_check(message, expected_seq),
            self.detect_replay(message, history),
            self.detect_delay(message, max_delay),
        ]

        attacks = [r for r in results if r.is_attack]
        if not attacks:
            return DetectionResult(
                is_attack=False,
                attack_type="none",
                confidence=1.0,
                details={"checks_passed": len(results)},
            )

        # Return the result with the highest confidence
        return max(attacks, key=lambda r: r.confidence)
