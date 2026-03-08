"""Statistical analysis and reporting for SDVN attack detection."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


@dataclass
class _Event:
    event_type: str
    details: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)


class AttackStatistics:
    """Tracks detection events and computes performance metrics.

    Differentiates between true positives (actual attacks detected),
    false positives (benign messages incorrectly flagged) and
    true negatives (benign messages correctly passed).
    """

    def __init__(self) -> None:
        self._events: List[_Event] = []

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_event(self, event_type: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Record a detection event.

        Args:
            event_type: One of ``'true_positive'``, ``'false_positive'``,
                ``'true_negative'``, ``'false_negative'``, or a custom
                attack label.
            details: Arbitrary metadata dictionary.
        """
        self._events.append(
            _Event(event_type=event_type, details=details or {})
        )

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def get_detection_rate(self) -> float:
        """Compute the true-positive detection rate (recall).

        Returns:
            Ratio of true positives to all actual attacks, or ``0.0``
            if no attack events have been recorded.
        """
        tp = sum(1 for e in self._events if e.event_type == "true_positive")
        fn = sum(1 for e in self._events if e.event_type == "false_negative")
        total = tp + fn
        return tp / total if total > 0 else 0.0

    def get_false_positive_rate(self) -> float:
        """Compute the false positive rate.

        Returns:
            Ratio of false positives to all benign messages, or ``0.0``
            if no benign events have been recorded.
        """
        fp = sum(1 for e in self._events if e.event_type == "false_positive")
        tn = sum(1 for e in self._events if e.event_type == "true_negative")
        total = fp + tn
        return fp / total if total > 0 else 0.0

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_report(self) -> Dict[str, Any]:
        """Build a summary report dictionary.

        Returns:
            Dictionary with counts per event type, detection rate,
            false positive rate and total event count.
        """
        counts: Dict[str, int] = {}
        for e in self._events:
            counts[e.event_type] = counts.get(e.event_type, 0) + 1

        return {
            "total_events": len(self._events),
            "event_counts": counts,
            "detection_rate": self.get_detection_rate(),
            "false_positive_rate": self.get_false_positive_rate(),
        }

    def plot_timeline(self, output_path: Optional[str] = None) -> None:
        """Plot detection events on a timeline.

        Args:
            output_path: If provided, the figure is saved here instead of
                being displayed interactively.
        """
        if not self._events:
            return

        start_ts = self._events[0].timestamp
        times = [e.timestamp - start_ts for e in self._events]
        labels = [e.event_type for e in self._events]

        colour_map = {
            "true_positive": "#e74c3c",
            "false_positive": "#e67e22",
            "true_negative": "#2ecc71",
            "false_negative": "#3498db",
        }
        colours = [colour_map.get(lbl, "#95a5a6") for lbl in labels]

        fig, ax = plt.subplots(figsize=(12, 4))
        ax.scatter(times, [1] * len(times), c=colours, s=80, zorder=3)
        ax.set_xlabel("Time (s)")
        ax.set_title("Detection Event Timeline")
        ax.set_yticks([])

        # Legend
        from matplotlib.patches import Patch
        unique_types = list(dict.fromkeys(labels))
        legend_handles = [
            Patch(facecolor=colour_map.get(t, "#95a5a6"), label=t)
            for t in unique_types
        ]
        ax.legend(handles=legend_handles, loc="upper right")

        plt.tight_layout()
        if output_path:
            plt.savefig(output_path, bbox_inches="tight")
            plt.close()
        else:
            plt.show()
