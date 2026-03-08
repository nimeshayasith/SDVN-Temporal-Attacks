"""Main SDVN simulation engine."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.network.topology import SDVNTopology
from src.network.vehicle import Vehicle, Message
from src.network.controller import SDNController
from src.attacks.replay_attack import ReplayAttack
from src.attacks.delay_attack import DelayAttack
from src.attacks.timing_attack import TimingAttack
from src.detection.detector import TemporalAttackDetector, DetectionResult
from src.detection.statistics import AttackStatistics


@dataclass
class SimulationConfig:
    """Configuration parameters for an SDVN simulation run.

    Attributes:
        num_vehicles: Number of vehicle nodes.
        num_rsus: Number of Road Side Units.
        area_size: Simulated area in metres ``(width, height)``.
        rsu_range: RSU communication range in metres.
        message_rate: Messages generated per second per vehicle.
        attack_probability: Probability that any given message is attacked.
        timestamp_window: Acceptable message age in seconds.
        max_delay_threshold: Max acceptable transmission delay in seconds.
    """

    num_vehicles: int = 10
    num_rsus: int = 4
    area_size: tuple = (1000.0, 1000.0)
    rsu_range: float = 300.0
    message_rate: float = 1.0
    attack_probability: float = 0.3
    timestamp_window: float = 5.0
    max_delay_threshold: float = 2.0


class SDVNSimulator:
    """Integrates topology, vehicles, controller, attacks and detection.

    Typical usage::

        sim = SDVNSimulator()
        sim.setup(num_vehicles=10, num_rsus=4)
        results = sim.run(duration_seconds=60, attack_type="replay")
    """

    def __init__(self, config: Optional[SimulationConfig] = None) -> None:
        self.config = config or SimulationConfig()
        self.topology = SDVNTopology(area_size=self.config.area_size)
        self.controller = SDNController()
        self.detector = TemporalAttackDetector()
        self.stats = AttackStatistics()
        self.vehicles: List[Vehicle] = []
        self._message_history: List[Message] = []
        self._results: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def setup(
        self,
        num_vehicles: Optional[int] = None,
        num_rsus: Optional[int] = None,
    ) -> None:
        """Initialise topology, vehicles and controller.

        Args:
            num_vehicles: Override ``config.num_vehicles``.
            num_rsus: Override ``config.num_rsus``.
        """
        nv = num_vehicles or self.config.num_vehicles
        nr = num_rsus or self.config.num_rsus

        self.topology.create_topology(
            num_rsus=nr,
            num_vehicles=nv,
            rsu_range=self.config.rsu_range,
        )

        # Create Vehicle objects for each vehicle node
        self.vehicles = []
        for node_id, data in self.topology.graph.nodes(data=True):
            if data.get("type") == "vehicle":
                v = Vehicle(
                    vehicle_id=node_id,
                    position=data["position"],
                    speed=random.uniform(5, 30),
                    direction=random.uniform(0, 360),
                )
                self.vehicles.append(v)
                self.controller.register_node({"node_id": node_id, "type": "vehicle"})

        # Register RSUs
        for node_id, data in self.topology.graph.nodes(data=True):
            if data.get("type") == "rsu":
                self.controller.register_node({"node_id": node_id, "type": "rsu"})

        self.controller.set_topology(self.topology.graph)

    # ------------------------------------------------------------------
    # Attack injection
    # ------------------------------------------------------------------

    def inject_attack(
        self,
        attack_type: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Inject a single attack event.

        Args:
            attack_type: One of ``'replay'``, ``'delay'``, ``'timing'``.
            params: Optional override parameters for the attack.

        Returns:
            Dictionary describing the attack outcome.
        """
        params = params or {}
        if len(self.vehicles) < 2:
            return {"error": "Need at least 2 vehicles"}

        src, dst = random.sample(self.vehicles, 2)

        if attack_type == "replay":
            attacker = ReplayAttack()
            msg = src.send_message(dst.vehicle_id, {"type": "beacon", "seq": 1})
            attacker.capture_message(msg)
            replayed = attacker.replay(dst, delay=0.0)
            return {"attack": "replay", "replayed_count": len(replayed)}

        if attack_type == "delay":
            attacker_d = DelayAttack()
            msg = src.send_message(dst.vehicle_id, {"type": "beacon"})
            attacker_d.intercept(msg)
            attacker_d.inject_delayed(msg, delay_seconds=0.0, target_node=dst)
            return {"attack": "delay", "delay_seconds": params.get("delay", 0.0)}

        if attack_type == "timing":
            attacker_t = TimingAttack()
            msgs = [src.send_message(dst.vehicle_id, {"i": i}) for i in range(5)]
            attacker_t.observe_timing(msgs)
            pattern = attacker_t.analyze_pattern()
            return {"attack": "timing", "pattern": pattern}

        return {"error": f"Unknown attack type: {attack_type}"}

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(
        self,
        duration_seconds: int = 60,
        attack_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute the simulation for *duration_seconds* simulated seconds.

        Each simulated second:
        - Every vehicle generates a message to a random peer.
        - With probability ``config.attack_probability`` (when
          *attack_type* is set) the message is attacked and re-analysed.
        - The detector analyses every message.

        Args:
            duration_seconds: Simulated duration in seconds.
            attack_type: Attack to inject, or ``None`` for baseline.

        Returns:
            Result dictionary (also accessible via :meth:`get_results`).
        """
        total_messages = 0
        detected_attacks = 0
        false_positives = 0

        for tick in range(duration_seconds):
            for vehicle in self.vehicles:
                if not self.vehicles:
                    break
                peers = [v for v in self.vehicles if v.vehicle_id != vehicle.vehicle_id]
                if not peers:
                    continue
                dest = random.choice(peers)
                msg = vehicle.send_message(dest.vehicle_id, {"tick": tick, "type": "beacon"})
                total_messages += 1

                is_actual_attack = False

                # Possibly inject an attack
                if attack_type and random.random() < self.config.attack_probability:
                    is_actual_attack = True
                    if attack_type == "replay":
                        # Replay: reuse msg_id so detector catches it
                        if self._message_history:
                            msg = random.choice(self._message_history)
                    elif attack_type == "delay":
                        # Delay: back-date the timestamp
                        msg.timestamp -= self.config.max_delay_threshold * 3
                    elif attack_type == "timing":
                        # Timing: inject future timestamp anomaly
                        msg.timestamp += 100.0

                result: DetectionResult = self.detector.analyze_message(
                    msg,
                    context={
                        "message_history": self._message_history,
                        "expected_seq": msg.sequence_number,
                        "max_delay": self.config.max_delay_threshold,
                        "timestamp_window": self.config.timestamp_window,
                    },
                )

                if result.is_attack and is_actual_attack:
                    self.stats.record_event("true_positive", result.details)
                    detected_attacks += 1
                elif result.is_attack and not is_actual_attack:
                    self.stats.record_event("false_positive", result.details)
                    false_positives += 1
                elif not result.is_attack and not is_actual_attack:
                    self.stats.record_event("true_negative", {})
                else:
                    self.stats.record_event("false_negative", result.details)

                self._message_history.append(msg)
                # Bound history size to avoid excessive memory use
                if len(self._message_history) > 1000:
                    self._message_history = self._message_history[-500:]

        report = self.stats.generate_report()
        self._results = {
            "total_messages": total_messages,
            "detected_attacks": detected_attacks,
            "false_positives": false_positives,
            "attack_type": attack_type or "none",
            "duration_seconds": duration_seconds,
            "detection_rate": report["detection_rate"],
            "false_positive_rate": report["false_positive_rate"],
            "event_counts": report["event_counts"],
        }
        return self._results

    def get_results(self) -> Dict[str, Any]:
        """Return the results of the last simulation run."""
        return dict(self._results)
