# SDVN Temporal Attacks

**Final Year Project** – Simulation and Detection of Temporal Attacks in Software Defined Vehicular Networks (SDVN).

## Overview

This project implements a Python-based simulation framework for studying **temporal attacks** in Software Defined Vehicular Networks. The simulator models an SDN-controlled vehicular environment with Road Side Units (RSUs) and mobile vehicle nodes, and provides tools to inject and detect the following attack types:

| Attack | Description |
|--------|-------------|
| **Replay Attack** | Captured legitimate messages are re-injected to confuse receiving nodes |
| **Delay Attack** | Messages are intentionally held back to create timing inconsistencies |
| **Timing Attack** | Inter-arrival timing patterns are observed to infer private routing information |

A multi-layered **TemporalAttackDetector** provides:
- Timestamp freshness validation
- Sequence number verification
- Duplicate message (replay) detection
- Excessive delay detection

---

## Project Structure

```
SDVN-Temporal-Attacks/
├── main.py                      # CLI entry point
├── requirements.txt             # Python dependencies
├── src/
│   ├── network/
│   │   ├── topology.py          # SDVNTopology – graph-based network model
│   │   ├── vehicle.py           # Vehicle node and Message dataclass
│   │   └── controller.py        # SDNController – routing and flow tables
│   ├── attacks/
│   │   ├── replay_attack.py     # ReplayAttack – capture & re-inject messages
│   │   ├── delay_attack.py      # DelayAttack – intercept & delay messages
│   │   └── timing_attack.py     # TimingAttack – inter-arrival pattern analysis
│   ├── detection/
│   │   ├── detector.py          # TemporalAttackDetector + DetectionResult
│   │   └── statistics.py        # AttackStatistics – metrics & reporting
│   └── simulation/
│       ├── simulator.py         # SDVNSimulator – integrates all components
│       └── scenario.py          # Pre-built scenarios (replay/delay/timing/baseline)
└── tests/
    ├── test_topology.py         # Network topology unit tests
    ├── test_detector.py         # Detector unit tests
    └── test_attacks.py          # Attack module unit tests
```

---

## Requirements

- Python 3.8+
- Dependencies listed in `requirements.txt` (numpy, matplotlib, networkx, pandas, scipy)

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

Run a simulation scenario from the command line:

```bash
python main.py --scenario <scenario> [--vehicles N] [--rsus N] [--duration S] [--output results.json]
```

### Available Scenarios

| Scenario | Description |
|----------|-------------|
| `baseline` | No attacks – establishes normal traffic baseline |
| `replay` | Simulates replay attacks with detection |
| `delay` | Simulates delay attacks with detection |
| `timing` | Simulates timing attacks with detection |

### Examples

```bash
# Baseline (no attacks), 10 vehicles, 60 seconds
python main.py --scenario baseline --vehicles 10 --duration 60

# Replay attack scenario, 20 vehicles, 120 seconds, save results
python main.py --scenario replay --vehicles 20 --duration 120 --output results.json

# Delay attack with custom attack probability
python main.py --scenario delay --vehicles 15 --duration 90 --attack-prob 0.4
```

### CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--scenario` | `baseline` | Scenario to run (`baseline`, `replay`, `delay`, `timing`) |
| `--vehicles` | `10` | Number of vehicle nodes |
| `--rsus` | `4` | Number of Road Side Units |
| `--duration` | `60` | Simulation duration in seconds |
| `--attack-prob` | `0.3` | Attack injection probability per message (0–1) |
| `--output` | _(none)_ | Path to save JSON results |

---

## Running Tests

```bash
python -m pytest tests/ -v
```

All 40 unit tests should pass.

---

## Architecture

```
SDVNSimulator
├── SDVNTopology     (networkx graph: controller → RSUs → vehicles)
├── SDNController    (routing, flow-table management)
├── Vehicle nodes    (message send/receive, timestamp tracking)
├── Attack modules   (ReplayAttack / DelayAttack / TimingAttack)
├── TemporalAttackDetector (4-check pipeline)
└── AttackStatistics (detection rate, false-positive rate, timeline)
```

---

## License

This project is developed as part of a Final Year Project. All rights reserved.
