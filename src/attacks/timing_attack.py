"""Timing attack module for SDVN temporal attack simulation."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from src.network.vehicle import Message


class TimingAttack:
    """Analyses inter-message timing to infer routing and network topology.

    A passive attacker observes message timestamps and uses statistical
    analysis of inter-arrival times to estimate the likely forwarding
    path or identify timing side-channels.
    """

    def __init__(self, attacker_id: str = "timing_attacker") -> None:
        self.attacker_id = attacker_id
        self._observations: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def observe_timing(self, message_stream: List[Message]) -> None:
        """Record timing observations from a stream of messages.

        Args:
            message_stream: Ordered list of observed messages.
        """
        for i, msg in enumerate(message_stream):
            prev_ts = message_stream[i - 1].timestamp if i > 0 else msg.timestamp
            self._observations.append(
                {
                    "msg_id": msg.msg_id,
                    "sender_id": msg.sender_id,
                    "timestamp": msg.timestamp,
                    "inter_arrival": msg.timestamp - prev_ts,
                    "sequence_number": msg.sequence_number,
                }
            )

    def analyze_pattern(self) -> Dict[str, Any]:
        """Compute statistical features from the collected observations.

        Returns:
            Dictionary with ``mean_inter_arrival``, ``std_inter_arrival``,
            ``min_inter_arrival``, ``max_inter_arrival``,
            ``observation_count`` and ``unique_senders``.
        """
        if not self._observations:
            return {}

        inter_arrivals = [o["inter_arrival"] for o in self._observations]
        arr = np.array(inter_arrivals)
        unique_senders = list({o["sender_id"] for o in self._observations})

        return {
            "mean_inter_arrival": float(np.mean(arr)),
            "std_inter_arrival": float(np.std(arr)),
            "min_inter_arrival": float(np.min(arr)),
            "max_inter_arrival": float(np.max(arr)),
            "observation_count": len(self._observations),
            "unique_senders": unique_senders,
        }

    def estimate_route(
        self, timing_data: Optional[List[Dict[str, Any]]] = None
    ) -> List[str]:
        """Estimate the forwarding route from timing data.

        Uses the observation that each hop adds a detectable propagation
        delay.  Consecutive mean inter-arrival clusters are mapped to
        inferred hop nodes.

        Args:
            timing_data: Optional external timing data to analyse.  If
                ``None``, the internally collected observations are used.

        Returns:
            Ordered list of inferred node identifiers along the estimated
            route.
        """
        data = timing_data if timing_data is not None else self._observations
        if not data:
            return []

        # Group by sender; sort clusters by mean timestamp
        sender_times: Dict[str, List[float]] = {}
        for obs in data:
            sender_times.setdefault(obs["sender_id"], []).append(obs["timestamp"])

        # Infer hop order from mean observed timestamp per sender
        ordered = sorted(sender_times.items(), key=lambda kv: np.mean(kv[1]))
        return [sender for sender, _ in ordered]

    def clear(self) -> None:
        """Reset all observations."""
        self._observations.clear()
