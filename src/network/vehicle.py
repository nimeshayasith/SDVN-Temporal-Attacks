"""Vehicle node and message dataclasses for SDVN simulation."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Message:
    """A network message transmitted between SDVN nodes.

    Attributes:
        msg_id: Unique message identifier.
        sender_id: Originating node identifier.
        receiver_id: Destination node identifier.
        data: Arbitrary payload.
        timestamp: Unix timestamp at creation time.
        sequence_number: Per-sender monotonic sequence counter.
    """

    msg_id: str
    sender_id: str
    receiver_id: str
    data: Any
    timestamp: float
    sequence_number: int


class Vehicle:
    """Represents a vehicle node in the SDVN.

    Attributes:
        vehicle_id: Unique identifier for the vehicle.
        position: Current ``(x, y)`` position in metres.
        speed: Speed in m/s.
        direction: Heading angle in degrees (0 = east, 90 = north).
    """

    def __init__(
        self,
        vehicle_id: str,
        position: Tuple[float, float] = (0.0, 0.0),
        speed: float = 0.0,
        direction: float = 0.0,
    ) -> None:
        self.vehicle_id = vehicle_id
        self.position = position
        self.speed = speed
        self.direction = direction
        self._sequence_counter: int = 0
        self._last_timestamp: float = time.time()
        self._inbox: List[Message] = []

    # ------------------------------------------------------------------
    # Messaging
    # ------------------------------------------------------------------

    def send_message(self, destination: str, data: Any) -> Message:
        """Create and return a new :class:`Message` addressed to *destination*.

        Args:
            destination: Receiver node identifier.
            data: Payload to include.

        Returns:
            The newly constructed :class:`Message`.
        """
        self._sequence_counter += 1
        msg = Message(
            msg_id=str(uuid.uuid4()),
            sender_id=self.vehicle_id,
            receiver_id=destination,
            data=data,
            timestamp=time.time(),
            sequence_number=self._sequence_counter,
        )
        self._last_timestamp = msg.timestamp
        return msg

    def receive_message(self, message: Message) -> None:
        """Store an incoming *message* in the vehicle's inbox.

        Args:
            message: The received :class:`Message`.
        """
        self._inbox.append(message)

    def get_status(self) -> Dict[str, Any]:
        """Return a snapshot of the vehicle's current state.

        Returns:
            Dictionary with ``vehicle_id``, ``position``, ``speed``,
            ``direction``, ``last_timestamp`` and ``inbox_size``.
        """
        return {
            "vehicle_id": self.vehicle_id,
            "position": self.position,
            "speed": self.speed,
            "direction": self.direction,
            "last_timestamp": self._last_timestamp,
            "inbox_size": len(self._inbox),
        }

    # ------------------------------------------------------------------
    # Movement helpers
    # ------------------------------------------------------------------

    def update_position(self, dt: float) -> None:
        """Advance the vehicle position by one time-step of *dt* seconds."""
        import math

        dx = self.speed * math.cos(math.radians(self.direction)) * dt
        dy = self.speed * math.sin(math.radians(self.direction)) * dt
        self.position = (self.position[0] + dx, self.position[1] + dy)
