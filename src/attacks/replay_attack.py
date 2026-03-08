"""Replay attack module for SDVN temporal attack simulation."""

from __future__ import annotations

import copy
import time
from typing import List, Optional

from src.network.vehicle import Message, Vehicle


class ReplayAttack:
    """Simulates a replay attack by capturing and re-injecting messages.

    An attacker captures legitimate messages and replays them later,
    optionally with modified timestamps, to confuse receiving nodes.
    """

    def __init__(self, attacker_id: str = "replay_attacker") -> None:
        self.attacker_id = attacker_id
        self._captured: List[Message] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def capture_message(self, message: Message) -> None:
        """Store a copy of *message* for later replay.

        Args:
            message: The legitimate message to capture.
        """
        self._captured.append(copy.deepcopy(message))

    def replay(
        self,
        target_node: Vehicle,
        delay: float = 0.0,
        modify_timestamp: bool = True,
    ) -> List[Message]:
        """Replay all captured messages to *target_node*.

        Args:
            target_node: The victim :class:`~src.network.vehicle.Vehicle`.
            delay: Additional artificial delay added on top of natural
                capture-to-replay time (seconds).
            modify_timestamp: If ``True`` the replayed message timestamp
                is set to the current time so it superficially appears
                fresh.

        Returns:
            List of replayed :class:`~src.network.vehicle.Message` objects.
        """
        if delay > 0:
            time.sleep(delay)

        replayed: List[Message] = []
        for original in self._captured:
            msg = copy.deepcopy(original)
            if modify_timestamp:
                msg.timestamp = time.time()
            target_node.receive_message(msg)
            replayed.append(msg)
        return replayed

    def get_captured_messages(self) -> List[Message]:
        """Return the list of captured messages (read-only copy).

        Returns:
            Shallow copy of the internal capture buffer.
        """
        return list(self._captured)

    def clear(self) -> None:
        """Discard all captured messages."""
        self._captured.clear()
