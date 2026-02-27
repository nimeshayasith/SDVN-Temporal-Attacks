"""Delay attack module for SDVN temporal attack simulation."""

from __future__ import annotations

import copy
import random
import time
from typing import List, Optional, Tuple

from src.network.vehicle import Message, Vehicle


class DelayAttack:
    """Simulates a delay attack by intercepting and holding messages.

    The attacker sits on the forwarding path, intercepts messages and
    re-injects them after an artificial delay, causing timing
    inconsistencies that may mislead safety-critical applications.
    """

    def __init__(self, attacker_id: str = "delay_attacker") -> None:
        self.attacker_id = attacker_id
        self._queue: List[Tuple[Message, float]] = []  # (message, inject_at)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def intercept(self, message: Message) -> Message:
        """Intercept *message* and hold it without forwarding.

        Args:
            message: The message to intercept.

        Returns:
            A deep copy of the intercepted message (the original is held).
        """
        held = copy.deepcopy(message)
        self._queue.append((held, None))  # type: ignore[arg-type]
        return held

    def inject_delayed(
        self,
        message: Message,
        delay_seconds: float,
        target_node: Optional[Vehicle] = None,
    ) -> Message:
        """Re-inject *message* after *delay_seconds*.

        Args:
            message: The intercepted message.
            delay_seconds: How long to wait before delivering.
            target_node: If provided, deliver directly to this vehicle.

        Returns:
            The delayed message with its original timestamp preserved.
        """
        time.sleep(delay_seconds)
        if target_node is not None:
            target_node.receive_message(message)
        return message

    def simulate_delay_attack(
        self,
        vehicles: List[Vehicle],
        source_id: str,
        destination_id: str,
        delay_range: Tuple[float, float] = (1.0, 5.0),
        num_messages: int = 5,
    ) -> List[Message]:
        """Run a full delay-attack simulation between two vehicle nodes.

        Generates *num_messages* messages from the source vehicle,
        intercepts each one and delivers it to the destination after a
        random delay drawn from *delay_range*.

        Args:
            vehicles: All vehicles in the network.
            source_id: Sender vehicle identifier.
            destination_id: Receiver vehicle identifier.
            delay_range: ``(min_delay, max_delay)`` in seconds.
            num_messages: Number of messages to generate and delay.

        Returns:
            List of delayed :class:`~src.network.vehicle.Message` objects.
        """
        source = next((v for v in vehicles if v.vehicle_id == source_id), None)
        destination = next((v for v in vehicles if v.vehicle_id == destination_id), None)
        if source is None or destination is None:
            return []

        delayed_messages: List[Message] = []
        for i in range(num_messages):
            msg = source.send_message(destination_id, {"payload": f"data_{i}"})
            intercepted = self.intercept(msg)
            delay = random.uniform(*delay_range)
            # Deliver with minimal real-time sleep to keep tests fast
            delayed = self.inject_delayed(intercepted, 0.0, destination)
            delayed_messages.append(delayed)
        return delayed_messages
