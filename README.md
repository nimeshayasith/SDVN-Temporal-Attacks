# SDVN Temporal-Echo Topology Attacks

Final Year Project codebase for studying temporal-echo topology attacks in Software-Defined Vehicular Networks (SDVNs).

> Main implementation file: `routing.cc`
>
> Note: `sdvn-temporal-attacks.cc` is not the main file for this project. The correct file to study and extend is `routing.cc`.

## Project Idea

This project studies how an SDVN controller can be misled when attackers reuse valid control-plane information at the wrong time, with the wrong identity, or through false repeated topology evidence.

In a normal SDVN, vehicles and RSUs send status information such as position, velocity, acceleration, neighbor lists, heartbeat-like messages, and routing metadata. The controller or management node uses this information to build a global view of the network and choose routes.

The security problem is that the controller may trust messages that look valid but are temporally or spatially misleading. For example, an attacker can replay an old topology update after a real link has already broken. The packet may look normal, but it makes the controller believe in a link that no longer exists.

The final project proposal describes three attack families:

1. Topology Time-Warp (TTW)
2. Beacon State Heartbeat Hijack (BSHH)
3. Multipath Echo (ME)

Each attack family has four attacker-placement variants:

1. Malicious vehicle, without RSU
2. Malicious RSU, with RSU infrastructure
3. Malicious controller, without RSU
4. Malicious controller, with RSU infrastructure

That gives the planned 12 attack variants:

| Family | Variant | Meaning |
| --- | --- | --- |
| TTW | TTW-S1 | Malicious vehicle replays or forges timing of topology information |
| TTW | TTW-S2 | Malicious RSU changes timing while forwarding vehicle messages |
| TTW | TTW-S3 | Malicious controller internally changes message timing without RSU |
| TTW | TTW-S4 | Malicious controller or controller-side logic changes timing with RSU support |
| BSHH | BSHH-S1 | Malicious vehicle hijacks heartbeat identity |
| BSHH | BSHH-S2 | Malicious RSU rewrites heartbeat sender identity |
| BSHH | BSHH-S3 | Malicious controller creates false heartbeat/liveness state without RSU |
| BSHH | BSHH-S4 | Malicious controller creates false heartbeat/liveness state with RSU |
| ME | ME-S1 | Malicious vehicles duplicate legitimate topology evidence to create phantom paths |
| ME | ME-S2 | Malicious RSU injects duplicated topology evidence |
| ME | ME-S3 | Malicious controller internally duplicates topology links without RSU |
| ME | ME-S4 | Malicious controller internally duplicates topology links with RSU |

The current `routing.cc` already contains one attack entry point:

```text
attack_scenario == 4
```

This is currently used for a TTW attack scenario with a malicious vehicle and no RSUs. Future work can extend the same style to the remaining 11 variants.

## What `routing.cc` Does

`routing.cc` is a large ns-3 simulation file. It combines:

- VANET / SDVN network simulation
- vehicles, RSUs, controller node, and management node
- DSRC / WAVE / WiFi communication
- LTE and CSMA communication paths
- AODV support
- custom ns-3 packet tags
- topology and neighbor discovery
- routing metadata collection
- routing algorithms
- optimization / prediction data export through CSV files
- performance metric calculation
- one currently wired attack scenario
- NetAnim visualization support

Think of the file as a complete experimental simulator, not just a small routing program.

## Beginner Concepts You Should Know First

### ns-3

ns-3 is a network simulator. Instead of running real vehicles or real routers, the code creates simulated nodes, devices, wireless channels, packets, and events.

Important ns-3 ideas used in this file:

- `Node`: a simulated device such as a vehicle, RSU, controller, or management server.
- `NodeContainer`: a group of nodes.
- `NetDevice`: a network interface installed on a node.
- `WifiNetDevice`: a WiFi / DSRC-style interface.
- `MobilityModel`: controls node position and movement.
- `Simulator::Schedule`: schedules a function to run at a future simulation time.
- `Simulator::Run`: starts the simulation.
- `Simulator::Stop`: defines when the simulation ends.
- `Tag`: metadata attached to packets.
- `Application`: a traffic-generating or packet-handling program installed on a node.
- `AnimationInterface`: writes NetAnim visualization output.

### SDVN

SDVN means Software-Defined Vehicular Network. The idea is similar to SDN, but for vehicular networks:

- vehicles and RSUs form the data/communication layer
- the controller maintains a global view
- the controller or management node computes routes
- vehicles send metadata so the controller can update its view

### Temporal-Echo Attack

A temporal-echo attack does not always create a completely fake packet. Instead, it often reuses valid old information in a wrong context.

Examples:

- replaying an old link after the link is broken
- changing the timestamp of an old message
- pretending a heartbeat came from another vehicle
- duplicating a real link report through multiple false witnesses

That is why these attacks are subtle: the message content can look legitimate, but the timing, identity, or reporting path is wrong.

## `routing.cc` Section-by-Section Guide

The line numbers below are approximate because the file contains very long lines and different editors may count wrapped lines differently.

### 1. Includes and Namespace Setup

Approximate location: top of `routing.cc`

This section imports ns-3 modules and standard C++ libraries.

Important modules:

- `wave-module`: WAVE / vehicular wireless support
- `wifi-module`: WiFi devices and channels
- `lte-module`: LTE communication support
- `aodv-module`: AODV routing protocol
- `internet-module`: IP stack
- `applications-module`: UDP and application helpers
- `mobility-module`: vehicle movement
- `netanim-module`: animation output

Importance:

This section decides what simulation features are available. If a module is missing from your ns-3 build, compilation can fail here.

Important note:

There is a visible typo near the namespace line:

```cpp
using namespace ns3;hjhjhj
```

That extra text is not valid C++. This README does not change code, but when you compile later, this is likely one of the first things to fix.

### 2. Global Constants and Simulation Parameters

Approximate location: near the top, after includes

This section defines the main simulation settings.

Important variables:

- `N_Vehicles`: number of vehicles
- `N_RSUs`: number of RSUs
- `simTime`: simulation duration
- `routing_algorithm`: selects which routing algorithm is used
- `experiment_number`: selects experiment style
- `data_transmission_frequency`: how often data transmission happens
- `optimization_frequency`: how often optimization runs
- `link_lifetime_threshold`: minimum acceptable predicted link lifetime
- `mobility_scenario`: controls movement setup
- `architecture`: centralized vs distributed style
- `maxspeed`: vehicle speed setting

Importance:

These variables are the main knobs of the experiment. When you run the simulation from the command line, many of them can be overridden using ns-3 `CommandLine`.

### 3. Attack Parameters

Approximate location: early in the file, before packet tag classes

Important variables:

- `attack_scenario`
- `malicious_vehicle_id`
- `victim_neighbor_id`
- `is_malicious_controller`
- `has_RSU_infrastructure`
- `TTW_HELLO_TIME`
- `TTW_LINK_BREAK`
- `TTW_REPLAY_TIME`
- `TTW_COMM_RANGE`

Importance:

This is the current attack-control area. It currently supports the existing TTW scenario logic. Future 12-variant work should probably expand this area with a clearer scenario numbering system.

Recommended future direction:

Instead of only `attack_scenario == 4`, create named scenario IDs such as:

```cpp
TTW_MALICIOUS_VEHICLE_NO_RSU = 1
TTW_MALICIOUS_RSU = 2
TTW_MALICIOUS_CONTROLLER_NO_RSU = 3
TTW_MALICIOUS_CONTROLLER_WITH_RSU = 4
...
```

That will make the 12 variants easier to read and test one by one.

### 4. TTW Attack Helper Functions

Approximate location: early file, before the many custom tag classes

Important functions:

- `TTW_InitLog`
- `TTW_SendHelloBeacon`
- `TTW_SendTopologyUpdate`
- `TTW_StorePacket`
- `TTW_ReplayAttack`

Concept:

This block models the current Topology Time-Warp idea.

The current timeline is:

1. At `t=10`, two vehicles exchange HELLO/topology information.
2. At `t=10`, the attacker stores an old valid packet.
3. At `t=15`, the physical link is considered broken.
4. At `t=20`, the attacker replays/forges the old topology information with a newer timestamp.
5. The controller accepts the wrong topology state.
6. The controller believes a broken link is still active.

Importance:

This is the clearest current attack implementation in `routing.cc`. It is the best starting point for learning how to add future attack variants.

### 5. Custom Packet Tag Classes

Approximate location: large middle section

The file contains many custom ns-3 `Tag` classes, including:

- `CustomDataTag`
- `CustomDataTag1` through many numbered versions
- `CustomDataTagmax`
- `CustomDataUnicastTag`
- `CustomDataUnicastTag1` through numbered versions
- many `CustomMetaDataUnicastTag...` classes

Concept:

In ns-3, a packet tag is metadata attached to a packet. The tag travels with the packet during simulation.

These tags store information such as:

- node ID
- position
- velocity
- acceleration
- timestamp
- neighbor IDs
- flow ID
- packet ID
- destination
- next hop
- channel information

Importance:

These tag classes are the data format of the simulator. If you want to implement attacks, you need to understand which tag carries the field you want to manipulate.

For example:

- TTW attacks focus on timestamp/topology freshness.
- BSHH attacks will likely focus on sender identity and heartbeat/liveness state.
- ME attacks will likely focus on neighbor/link evidence and duplicated topology reports.

Beginner tip:

Do not try to understand every generated tag class one by one at first. Many are repeated patterns. First understand one simple tag:

```cpp
CustomDataTag
```

Then understand how it serializes and deserializes fields:

- `Serialize`
- `Deserialize`
- `GetSerializedSize`
- getter functions
- setter functions

After that, the repeated tag classes become easier to recognize.

### 6. Node, Controller, Neighbor, and Routing Data Structures

Approximate location: after the large tag section

Important structs:

- `demanding_flow_struct_nodes`
- `demanding_flow_struct_controller`
- `controller_data`
- `routing_data_at_nodes`
- `routing_data_at_controller`
- `neighbor_data`
- `data_at_nodes`
- `data_at_manager`
- `routing_table`
- `proposed_routing_table`

Concept:

These structs are the simulator's memory. They store what each part of the network knows.

Examples:

- `neighbor_data` stores known neighbors of a node.
- `controller_data` stores what the controller believes.
- `data_at_nodes` stores local vehicle knowledge.
- `data_at_manager` stores management/global knowledge.
- routing tables store next-hop decisions.

Importance:

Temporal attacks are dangerous because these tables can become wrong. If the attacker poisons the data before it enters these tables, the routing decision can become unsafe.

For future attacks, this section helps answer:

- Where is the real network state stored?
- Where is the controller's believed state stored?
- Which table should become wrong during the attack?
- Which metric will show the attack impact?

### 7. Neighbor Discovery and Mobility Data

Important functions:

- `calculate_acceleration`
- `update_previous_velocity`
- `add_routing_data_at_nodes`
- `add_received_data_at_nodes`
- `refresh_neighbors`
- `refresh_controller_data`
- `add_neighbor_info`

Concept:

Vehicles move. Their position, velocity, acceleration, and neighbor list change over time.

This section collects and refreshes that information.

Importance:

In vehicular networks, a link can be valid at one moment and invalid soon after. That is exactly why temporal attacks matter. If the controller receives stale or replayed mobility/topology data, routing can be based on a past network state instead of the current one.

### 8. Entropy, Contention, and Delay Calculation

Important functions:

- `calculate_network_entropy`
- `calculate_wireless_entropy`
- `calculate_wired_entropy`
- `compute_Qbar`
- `compute_Qnei`
- `compute_wireless_average_delay`
- `compute_wired_average_delay`
- `compute_average_delays`
- `calculate_contention`

Concept:

The simulator measures how much the network state changes and how busy/delayed the network is.

Importance:

These values help decide whether optimization is needed and help evaluate routing performance.

For attack research, these metrics can help show:

- how much the attack changes the controller's view
- whether the attack increases delay
- whether the attack causes poor routing
- whether the network looks normal even while being poisoned

### 9. UDP Application Layer

Important class:

- `SimpleUdpApplication`

Concept:

This is a custom ns-3 application used to send packets between simulated nodes.

Importance:

Most simulated communication eventually goes through application-level send functions and packet callbacks. For future attacks, you may need to decide whether the attacker modifies packets:

- before sending
- while forwarding
- after receiving
- inside controller logic

### 10. CSV Writing, Reading, and Optimization Interface

Important functions:

- `write_csv`
- `write_csv_status_lifetime`
- `write_csv_status`
- `read_csv`
- `write_csv_results`
- `write_csv_results_routing`
- `optimize_first_time`
- `optimize_subsequent`
- `optimize_link_lifetime`
- `read_lifetime_from_csv`
- `run_optimization_first_time`
- `run_optimization_subsequent`
- `run_optimization_link_lifetime`

Concept:

The simulator writes network state into CSV files, calls or expects external optimization/prediction scripts, then reads results back.

Important file examples:

- `optimization_link_lifetime_data.csv`
- `optimization_link_lifetime_data_ECMP.csv`
- `link_lifetime_solution_ECMP.csv`
- `delay_training_data.csv`
- `delay_data_for_prediction.csv`
- `optimization_results.csv`

Importance:

This is the bridge between simulation and routing/learning logic. The C++ simulation produces data, and external scripts can produce predicted link lifetime or optimization decisions.

Important note:

Many paths are hardcoded to:

```text
/home/nimesha/ns-allinone-3.35/ns-3.35/scratch/
```

On Windows or on a different Linux username, those paths will need to be changed before running experiments.

### 11. Routing Algorithms

Important functions:

- `dijkstra`
- `generate_adjacency_matrix`
- `run_ECMP`
- `run_DCMR`
- `run_QRSDN`
- `run_RLMR`
- `run_proposed_RL`
- `run_stable_path_finding`
- `run_distance_path_finding`
- `calculate_dijkstra_solution`
- `calculate_dijkstra_stable_solution`

Concept:

This section computes paths through the vehicular network.

The code supports several routing approaches:

- ECMP: Equal-Cost Multi-Path style routing
- RR: Round-robin style behavior, currently scheduled similarly to ECMP in the switch block
- QR-SDN: Q-routing / SDN-inspired routing
- RLMR: reinforcement-learning based multipath routing
- Proposed RL: the main proposed reinforcement-learning routing logic
- DCMR: delay/cost-aware multipath routing
- Dijkstra: shortest-path baseline
- AODV: ad hoc routing baseline through ns-3

Importance:

Attack impact is finally visible here. If the topology view is wrong, the routing algorithm can choose a path that does not exist, is unstable, or has poor performance.

### 12. Performance Metrics

Important functions:

- `calculate_average_latency_routing`
- `calculate_average_packet_delivery_ratio_routing`
- `calculate_average_jitter_routing`
- `calculate_average_load_balance_routing`
- `calculate_average_latency`
- `calculate_packet_delivery_ratio`
- `calculate_average_channel_utilization`
- `calculate_average_cost_with_solution`
- `calculate_average_cost_without_solution`
- `calculate_aodv_packet_delivery_ratio`
- `calculate_aodv_latency`
- `calculate_performance_evaluation_metrics`

Concept:

These functions measure how well the network performs.

Important metrics:

- latency
- packet delivery ratio
- jitter
- load balance
- channel utilization
- routing cost
- optimization percentage

Importance:

For your final-year project, these metrics can compare:

- normal network vs attacked network
- one attack variant vs another attack variant
- before mitigation vs after mitigation
- routing algorithms under attack

### 13. Packet Transmission and Reception Logic

Important functions:

- `MacTx`
- `MacRx`
- `Rx`
- `Enqueue`
- `Dequeue`
- `check_delivery_and_retransmit`
- `dsrc_data_broadcast`
- `dsrc_metadata_broadcast`
- `dsrc_metadata_broadcast_subsequent`
- `centralized_dsrc_data_broadcast`
- `distributed_dsrc_data_broadcast`
- `routing_dsrc_data_unicast`
- `hybrid_data_unicast`
- `centralized_dsrc_data_unicast`
- `AODV_dataunicast_alone`
- `RSU_dataunicast_alone`
- `send_LTE_routing_data_alone`
- `send_LTE_data_alone`
- `RSU_routing_statusdataunicast_alone`
- `RSU_flowdata_unicast_alone`

Concept:

This section sends packets, receives packets, updates delivery state, and may retransmit packets when needed.

Importance:

This is where attack implementation may become concrete. Depending on the variant:

- malicious vehicle attacks may change data before sending
- malicious RSU attacks may change data while forwarding
- malicious controller attacks may change stored state after receiving
- ME attacks may duplicate valid link reports
- BSHH attacks may rewrite heartbeat identity
- TTW attacks may rewrite timestamps or replay stale topology information

### 14. Flow Setup and Scheduling

Important functions:

- `initialize_flow_counters`
- `check_and_transmit`
- `initiate_all_flows`
- `send_hybrid_packets`
- `send_centralized_packets`
- `send_distributed_packets`

Concept:

The simulation sends multiple flows. A flow has a source, destination, packet count, packet size, and QoS requirement.

Importance:

Routing attacks matter because they affect active flows. If the controller chooses a wrong path, the packet flow suffers.

### 15. Main Function

Approximate location: near the end of the file

Important responsibilities:

- initializes global data
- parses command-line arguments
- creates controller, management, vehicle, and RSU nodes
- sets mobility
- installs CSMA, LTE, WiFi, WAVE, and AODV components
- creates network devices
- installs applications
- schedules metadata collection
- schedules optimization
- schedules routing algorithm execution
- schedules packet flows
- configures NetAnim
- schedules TTW attack scenario 4 when enabled
- runs and destroys the simulation

Important command-line arguments:

```text
N_RSUs
N_Vehicles
data_transmission_frequency
link_lifetime_threshold
simTime
mobility_scenario
architecture
maxspeed
lambda
experiment_number
routing_test
routing_algorithm
qf
attack_scenario
malicious_vehicle_id
victim_neighbor_id
```

Importance:

`main()` is the experiment director. It decides what simulation exists and when each event happens.

## Current Attack Scenario in Code

The currently wired attack is controlled by:

```text
attack_scenario == 4
```

In this path:

- vehicles are created for the attack case
- V0 is treated as the attacker by default
- V1 is treated as the victim by default
- the victim moves away so the physical link breaks
- NetAnim colors are changed to highlight attacker, victim, and controller
- TTW helper functions are scheduled
- visual UDP packets are scheduled so NetAnim shows arrows
- a log file named `ttw_attack_scenario4.txt` is produced

Default attack timing:

| Time | Event |
| --- | --- |
| 10s | HELLO exchange and legitimate topology update |
| 10.2s | attacker stores old packet |
| 15s | link should be physically broken |
| 20s | attacker replays forged topology update |
| 20s | controller believes wrong topology |

## Suggested Roadmap for Implementing 12 Variants

Do not implement all attacks at once. Add one variant, test it, document it, then continue.

Recommended order:

1. Clean and confirm current TTW malicious vehicle scenario.
2. Add a clear enum or constants for all 12 scenarios.
3. Rename or remap the existing `attack_scenario == 4` to the correct TTW variant name.
4. Implement TTW variants first, because timestamp replay already exists.
5. Implement BSHH variants next, because they are identity/heartbeat changes.
6. Implement ME variants last, because they require duplicated link evidence and possibly multiple witnesses.
7. For each variant, define:
   - attacker node
   - victim node or victim link
   - whether RSU exists
   - whether controller is malicious
   - attack start time
   - exact packet field changed
   - expected wrong controller state
   - output log file
   - metric expected to change

Suggested scenario table:

| Scenario ID | Family | Attacker Placement | RSU? | Main Manipulation |
| --- | --- | --- | --- | --- |
| 1 | TTW | Vehicle | No | replay/forge timestamp |
| 2 | TTW | RSU | Yes | alter forwarded timestamp |
| 3 | TTW | Controller | No | alter stored topology time |
| 4 | TTW | Controller | Yes | alter RSU-forwarded topology time |
| 5 | BSHH | Vehicle | No | spoof heartbeat sender |
| 6 | BSHH | RSU | Yes | rewrite heartbeat identity |
| 7 | BSHH | Controller | No | create false liveness state |
| 8 | BSHH | Controller | Yes | create false liveness from RSU reports |
| 9 | ME | Vehicle | No | duplicate real link report |
| 10 | ME | RSU | Yes | inject duplicated topology report |
| 11 | ME | Controller | No | duplicate link internally |
| 12 | ME | Controller | Yes | duplicate RSU-confirmed link internally |

## How to Read the Code as a Beginner

Recommended reading order:

1. Read the global parameters first.
2. Read the attack parameters and TTW helper functions.
3. Read one packet tag class, especially `CustomDataTag`.
4. Skip the repeated tag classes on the first pass.
5. Read the data structures for neighbors, controller data, and routing tables.
6. Read the routing algorithm switch in `main()`.
7. Read `run_ECMP`, `run_QRSDN`, `run_RLMR`, `run_proposed_RL`, and `run_DCMR`.
8. Read the packet receive/send functions.
9. Read the metric calculation functions.
10. Finally read all of `main()` from top to bottom.

When learning, always ask:

- What data is being stored?
- Which node knows this data?
- Is this real physical state or controller-believed state?
- Which packet/tag carries this data?
- Which function sends it?
- Which function receives it?
- Which routing algorithm uses it?
- Which metric shows the result?

## Expected Build Environment

The code appears written for ns-3.35 style paths and APIs.

Expected tools:

- ns-3.35
- C++ compiler supported by ns-3
- Python for helper scripts
- NetAnim for animation viewing
- possibly SUMO for future mobility integration

The project currently contains helper/output CSV files:

- `optimization_link_lifetime_data.csv`
- `optimization_link_lifetime_data_ECMP.csv`
- `link_lifetime_solution_ECMP.csv`
- `optimization_lifetime_ECMP.py`

## Example Run Ideas

Exact commands depend on where `routing.cc` is placed inside ns-3.

If copied into the ns-3 `scratch` directory, a run may look like:

```bash
./waf --run "scratch/routing --simTime=30 --N_Vehicles=2 --N_RSUs=0 --attack_scenario=4"
```

For newer ns-3 versions:

```bash
./ns3 run "scratch/routing --simTime=30 --N_Vehicles=2 --N_RSUs=0 --attack_scenario=4"
```

Example routing algorithm selection:

```bash
./ns3 run "scratch/routing --routing_algorithm=4"
```

Routing algorithm IDs seen in `main()`:

| ID | Algorithm |
| --- | --- |
| 0 | ECMP |
| 1 | RR-like path, currently scheduled through `run_ECMP` |
| 2 | QR-SDN |
| 3 | RLMR |
| 4 | Proposed RL |
| 5 | DCMR |

## Important Output Files

Possible outputs include:

- `ttw_attack_scenario4.txt`
- NetAnim XML output
- routing result CSV files
- optimization input CSV files
- link lifetime solution CSV files
- AODV routing table output such as `aodv.routes`

Some output paths are hardcoded to Linux directories. If files do not appear, check the hardcoded paths in `write_csv...`, `read_csv...`, and optimization functions.

## Known Issues / Things to Check Before Compiling

This README documents the project without changing code. Before running, check these carefully:

1. Remove the stray text after `using namespace ns3;`.
2. Confirm the file is inside the correct ns-3 `scratch` directory.
3. Replace hardcoded `/home/nimesha/...` paths if your ns-3 folder is elsewhere.
4. Confirm all required ns-3 modules are enabled.
5. Confirm whether your ns-3 version uses `./waf` or `./ns3`.
6. Confirm generated CSV files exist before functions try to read them.
7. Test with small values first, such as `N_Vehicles=2`, `N_RSUs=0`, and `simTime=30`.

## Where Future Attack Code Should Likely Go

For future implementation, likely extension points are:

- attack parameters near the top of the file
- new attack helper functions near the existing `TTW_...` functions
- packet/tag manipulation in send/receive functions
- controller-state manipulation near controller data update logic
- scenario scheduling inside `main()`
- NetAnim coloring/description near the existing attack visualization block
- separate log files for each attack variant

Good implementation style:

- add one variant at a time
- keep each attack in its own helper function
- write a clear log file for each attack
- use scenario constants instead of magic numbers
- print expected and actual controller state
- compare normal run vs attack run
- save metrics for your final report

## Project Learning Goal

The most important idea in this project is not only "packets are attacked." The deeper idea is:

> The controller makes routing decisions from its believed network state. Temporal-echo attacks poison that believed state by replaying, delaying, duplicating, or rewriting otherwise valid control information.

So, when reading or extending `routing.cc`, always trace this path:

```text
vehicle/RSU/controller event
-> packet/tag data
-> receiver callback
-> stored controller or manager state
-> routing algorithm
-> selected path
-> performance metric
```

That trace is the backbone of the project.
