"""Entry point for the SDVN Temporal Attacks simulation."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Optional

from src.simulation.simulator import SimulationConfig
from src.simulation.scenario import (
    run_replay_attack_scenario,
    run_delay_attack_scenario,
    run_timing_attack_scenario,
    run_baseline_scenario,
)


SCENARIO_MAP = {
    "replay": run_replay_attack_scenario,
    "delay": run_delay_attack_scenario,
    "timing": run_timing_attack_scenario,
    "baseline": run_baseline_scenario,
}


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SDVN Temporal Attacks Simulation",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIO_MAP.keys()),
        default="baseline",
        help="Attack scenario to simulate.",
    )
    parser.add_argument(
        "--vehicles",
        type=int,
        default=10,
        help="Number of vehicle nodes.",
    )
    parser.add_argument(
        "--rsus",
        type=int,
        default=4,
        help="Number of Road Side Units.",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Simulation duration in seconds.",
    )
    parser.add_argument(
        "--attack-prob",
        type=float,
        default=0.3,
        dest="attack_prob",
        help="Probability of attack injection per message (0-1).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to save JSON results (optional).",
    )
    return parser.parse_args(argv)


def print_summary(results: Dict[str, Any]) -> None:
    """Print a human-readable summary of simulation results."""
    print("\n" + "=" * 55)
    print("  SDVN TEMPORAL ATTACKS SIMULATION RESULTS")
    print("=" * 55)
    print(f"  Scenario          : {results.get('scenario', results.get('attack_type', 'N/A'))}")
    print(f"  Duration          : {results.get('duration_seconds', 'N/A')} s")
    print(f"  Total messages    : {results.get('total_messages', 'N/A')}")
    print(f"  Detected attacks  : {results.get('detected_attacks', 'N/A')}")
    print(f"  False positives   : {results.get('false_positives', 'N/A')}")
    print(f"  Detection rate    : {results.get('detection_rate', 0.0):.2%}")
    print(f"  False positive rt : {results.get('false_positive_rate', 0.0):.2%}")
    print("-" * 55)
    counts = results.get("event_counts", {})
    if counts:
        print("  Event breakdown:")
        for event_type, count in sorted(counts.items()):
            print(f"    {event_type:<20} {count}")
    print("=" * 55 + "\n")


def main(argv=None) -> int:
    args = parse_args(argv)

    config = SimulationConfig(
        num_vehicles=args.vehicles,
        num_rsus=args.rsus,
        attack_probability=args.attack_prob,
    )

    # Override duration via a temporary config attribute used in scenarios
    config.num_vehicles = args.vehicles  # scenario uses num_vehicles * 3 by default

    scenario_fn = SCENARIO_MAP[args.scenario]

    print(f"Running '{args.scenario}' scenario with {args.vehicles} vehicles "
          f"for {args.duration} seconds …")

    # Build and run simulator directly to honour --duration
    from src.simulation.simulator import SDVNSimulator
    attack_type_map = {
        "replay": "replay",
        "delay": "delay",
        "timing": "timing",
        "baseline": None,
    }
    sim = SDVNSimulator(config=config)
    sim.setup(num_vehicles=args.vehicles, num_rsus=args.rsus)
    results = sim.run(
        duration_seconds=args.duration,
        attack_type=attack_type_map[args.scenario],
    )
    results["scenario"] = args.scenario

    print_summary(results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"Results saved to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
