# Summary of Our NS-3.35 Simulation Work

## Project focus

In this work, we extended the `routing.cc` simulation in NS-3.35 to model and study temporal-echo style attacks in a Software-Defined Vehicular Network (SDVN). The goal was to show how malicious entities can poison the controller's view of network topology or node liveness, and then evaluate how well the PEM-based detection layer can identify those attacks and support mitigation.

## What we built

Originally, the codebase already had the general SDVN simulation framework, routing support, DSRC/LTE communication flow, and an initial TTW-style attack prototype with PEM detection hooks. Our main contribution was turning that partial implementation into a complete attack-evaluation framework.

We implemented the full set of **12 attack scenarios**, grouped into three attack families:

1. **TTW (Topology Time-Warp)**  
   Replays old topology information with forged timestamps after a real link has already broken.

2. **BSHH (Beacon State Heartbeat Hijack)**  
   Replays or hijacks heartbeat information so the controller believes a vehicle is still alive or misidentifies the sender.

3. **ME (Multipath Echo)**  
   Injects duplicated or false observations so the controller believes extra path evidence exists for a link.

For each family, we supported four attacker placements:

- Malicious vehicle
- Malicious RSU
- Malicious controller without RSU support
- Malicious controller with RSU support

This produced the 12-scenario attack map used in the simulation:

- Scenario 0: baseline without attack
- Scenarios 1-4: TTW
- Scenarios 5-8: BSHH
- Scenarios 9-12: ME

## Main implementation contributions in `routing.cc`

The major coding work we completed includes:

- Reorganized and formalized the scenario numbering using the `AttackScenarioId` mapping so every attack variant has a fixed scenario ID.
- Expanded the attack logic from a single partial TTW case into a complete multi-family framework.
- Added dedicated data structures for each attack family, such as:
  - `TopologyPacket` handling for TTW logic
  - `HeartbeatPacket` for BSHH heartbeat replay and impersonation behavior
  - `MEEchoReport` for ME false reporter and phantom path behavior
- Added attack-state management through `declare_attack_states()` and `declare_attackers()` so malicious nodes/controllers can be assigned systematically using `attack_percentage`.
- Added support for controller-side malicious behavior as well as RSU-based attack paths.
- Added detailed per-scenario scheduling logic so each scenario reproduces a meaningful timeline of:
  - legitimate communication
  - packet/heartbeat storage
  - replay or forged reinsertion
  - topology poisoning consequences
- Integrated the attacks with PEM so detection can be evaluated immediately after attack events.

## Detection and evaluation work

Another important part of our contribution was connecting the implemented attacks to the PEM evaluation layer already present in the code. The simulation now records both the attack behavior and the detector response.

The framework measures:

- MCC
- AUROC
- detection latency (`Tdet`)
- packet delivery behavior under attack and after mitigation
- end-to-end delay impact

We also kept the **`detection_enabled`** option, which makes it possible to run:

- attack-only mode, where poisoning remains active and PEM does not mitigate
- attack-with-detection mode, where PEM can raise alerts and support mitigation

This is important because it lets us compare raw attack damage against protected system behavior.

Beyond simulation execution, we also used the generated results for performance analysis by plotting key evaluation graphs. In particular, we plotted:

- **MCC vs attack percentage**
- **AUROC vs attack percentage**
- **Detection latency vs attack percentage**

These graphs help show how detection performance changes as the proportion of malicious participants increases in the network.

## Output and experiment support

To make the simulation useful for analysis and report writing, we added structured output generation for each scenario. The code now writes scenario-based files for:

- `PEM_EVENT_LOG`
- `PEM_RUN_SUMMARY`
- `CHANNEL_DELIVERY_ANALYSIS`
- human-readable attack logs for TTW, BSHH, and ME variants
- per-scenario naming for cleaner experiment organization

This means each run can be traced clearly from:

- selected scenario
- attacker type and placement
- attack timeline
- detection result
- final performance metrics

## Overall result

In summary, our work transformed `routing.cc` from a mostly general SDVN simulator with one partial temporal attack example into a **complete NS-3.35 experimental framework for 12 temporal-echo attack scenarios**. The final implementation supports attacker modeling at the vehicle, RSU, and controller levels, integrates those behaviors with PEM-based detection, and produces the logs and metrics needed for evaluation, visualization, and report writing.

## Short conclusion for report use

We implemented and organized a full temporal-attack simulation framework in NS-3.35 for SDVNs. The final system models 12 attack scenarios across TTW, BSHH, and ME attack families, supports malicious vehicles, RSUs, and controllers, and evaluates each case using PEM-based detection metrics such as MCC, AUROC, detection latency, and packet delivery performance. We also analyzed the results by plotting MCC, AUROC, and detection latency against attack percentage to study how detector performance changes as attacker density increases. This implementation provides the practical simulation backbone for analyzing temporal topology poisoning attacks and the effectiveness of our proposed detection approach.
