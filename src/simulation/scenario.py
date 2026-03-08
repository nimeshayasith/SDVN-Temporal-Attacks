"""Predefined simulation scenarios for SDVN temporal attack evaluation."""

from __future__ import annotations

from typing import Any, Dict, Optional

from src.simulation.simulator import SDVNSimulator, SimulationConfig


def _build_simulator(config: Optional[SimulationConfig]) -> SDVNSimulator:
    sim = SDVNSimulator(config=config)
    sim.setup()
    return sim


def run_replay_attack_scenario(
    config: Optional[SimulationConfig] = None,
) -> Dict[str, Any]:
    """Run a simulation with replay attacks injected.

    Args:
        config: Simulation configuration; defaults applied if ``None``.

    Returns:
        Results dictionary from :meth:`~SDVNSimulator.get_results`.
    """
    cfg = config or SimulationConfig(attack_probability=0.4)
    sim = _build_simulator(cfg)
    results = sim.run(duration_seconds=cfg.num_vehicles * 3, attack_type="replay")
    results["scenario"] = "replay_attack"
    return results


def run_delay_attack_scenario(
    config: Optional[SimulationConfig] = None,
) -> Dict[str, Any]:
    """Run a simulation with delay attacks injected.

    Args:
        config: Simulation configuration; defaults applied if ``None``.

    Returns:
        Results dictionary from :meth:`~SDVNSimulator.get_results`.
    """
    cfg = config or SimulationConfig(attack_probability=0.4, max_delay_threshold=1.0)
    sim = _build_simulator(cfg)
    results = sim.run(duration_seconds=cfg.num_vehicles * 3, attack_type="delay")
    results["scenario"] = "delay_attack"
    return results


def run_timing_attack_scenario(
    config: Optional[SimulationConfig] = None,
) -> Dict[str, Any]:
    """Run a simulation with timing attacks injected.

    Args:
        config: Simulation configuration; defaults applied if ``None``.

    Returns:
        Results dictionary from :meth:`~SDVNSimulator.get_results`.
    """
    cfg = config or SimulationConfig(attack_probability=0.3, timestamp_window=2.0)
    sim = _build_simulator(cfg)
    results = sim.run(duration_seconds=cfg.num_vehicles * 3, attack_type="timing")
    results["scenario"] = "timing_attack"
    return results


def run_baseline_scenario(
    config: Optional[SimulationConfig] = None,
) -> Dict[str, Any]:
    """Run a baseline simulation with no attacks.

    Args:
        config: Simulation configuration; defaults applied if ``None``.

    Returns:
        Results dictionary from :meth:`~SDVNSimulator.get_results`.
    """
    cfg = config or SimulationConfig()
    sim = _build_simulator(cfg)
    results = sim.run(duration_seconds=cfg.num_vehicles * 3, attack_type=None)
    results["scenario"] = "baseline"
    return results
