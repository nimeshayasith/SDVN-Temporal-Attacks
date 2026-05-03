# Wireshark Integration Guide for NS-3 Temporal-Echo Attack Project

## Table of Contents

1. [How Wireshark Aligns with Your Project](#how-wireshark-aligns-with-your-project)
2. [How to Use Wireshark with Your Project](#how-to-use-wireshark-with-your-project)
3. [Specific Analysis for Your Attack Scenarios](#specific-analysis-for-your-attack-scenarios)
4. [Practical Detection Enhancement](#practical-detection-enhancement)

---

## How Wireshark Aligns with Your Project

### Overview

Your NS-3 simulator generates **simulated network packets** representing actual V2V (Vehicle-to-Vehicle), V2R (Vehicle-to-RSU), and RSU-to-Controller communications. Wireshark is a packet analyzer that can capture and inspect these simulated packets, providing deep visibility into the network behavior during attack scenarios.

### Key Alignment Points

#### 1. **Packet Trace Export**
- NS-3 can export simulated packet data to `.pcap` files (Packet Capture format)
- Wireshark natively reads `.pcap` files from any source (real networks or simulations)
- This allows you to replay and analyze simulated attack packets as if they were real

#### 2. **Three-Layer Verification**
```
┌─────────────────────────────────────────┐
│ Wireshark (Packet Layer)                │
│  ↓                                       │
│  What packets actually left the wire?   │
└─────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────┐
│ pem_event_log.csv (Detection Layer)     │
│  ↓                                       │
│  What did the controller see?           │
│  How did PEM score it?                  │
└─────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────┐
│ ttw_attack_scenario*.txt (Attack Log)   │
│  ↓                                       │
│  What did the attacker inject?          │
│  At what timestamp?                     │
└─────────────────────────────────────────┘
```

This three-way cross-reference validates your entire attack → transmission → detection pipeline.

#### 3. **Attack Scenario Validation**

For each of the 12 attack variants (TTW, BSHH, ME × 4 placements), Wireshark lets you:
- **Verify packet structure** — confirm your custom tags (TopologyPacket, HeartbeatPacket, MEEchoReport) are serialized correctly
- **Validate timing** — check that forged timestamps in attack packets differ from reception times
- **Inspect hop-by-hop paths** — trace V2V → RSU → Controller flow for RSU-involved scenarios
- **Detect anomalies** — identify where echo packets originate from unauthorized reporters

#### 4. **Channel-Level Analysis**

Your simulator uses 7 DSRC channels (172–184, with 178 as CCH). Wireshark can:
- Filter packets by channel frequency
- Measure per-channel delivery ratio (fanout)
- Identify if attack packets deviate from normal channel usage patterns
- Cross-reference with `channel_delivery_analysis.csv`

---

## How to Use Wireshark with Your Project

### Prerequisites

✅ **Wireshark is already installed** on your system:
```bash
wireshark --version
# Wireshark 3.6.2 (as of your environment)
```

### Step 1: Enable PCAP Tracing in `routing.cc`

Add these lines near the top of `main()`, **before** `Simulator::Run()`:

```cpp
// ─────────────────────────────────────────────────────────────────────────────
// PCAP TRACING — Enable packet capture for Wireshark analysis
// ─────────────────────────────────────────────────────────────────────────────

// Capture all DSRC 802.11p packets (V2V, V2R)
// Output: dsrc_trace-X-Y.pcap (X=node, Y=device index)
if (wifiPhyHelper != nullptr) {
    wifiPhyHelper.EnablePcapAll("dsrc_trace");
}

// Capture all CSMA Ethernet packets (RSU→Controller, Controller↔management)
// Output: csma_trace-X-Y.pcap
if (csmaHelper != nullptr) {
    csmaHelper.EnablePcapAll("csma_trace");
}

// Optional: LTE uplink packets (if LTE is enabled in your scenario)
// if (lteHelper != nullptr) {
//     lteHelper->EnablePcapAll("lte_trace");
// }
```

**Location in code:** Find the line `Simulator::Run()` and add the above block immediately before it (typically near line 140000+ in your routing.cc).

### Step 2: Run Your Simulation

```bash
cd ~/ns-3.35

# Run a specific attack scenario with PCAP tracing enabled
./waf --run "scratch/routing --simTime=30 --N_Vehicles=2 --N_RSUs=1 --attack_scenario=4"
```

**Output files generated:**
```
dsrc_trace-0-0.pcap    # DSRC device on node 0 (first vehicle)
dsrc_trace-1-0.pcap    # DSRC device on node 1 (second vehicle)
dsrc_trace-2-0.pcap    # DSRC device on node 2 (RSU or next node)
...
csma_trace-0-0.pcap    # CSMA device on controller/RSU node
csma_trace-1-0.pcap    # CSMA device on next node
...
```

### Step 3: Open PCAP Files in Wireshark

#### Option A: GUI (Graphical Interface)

```bash
# Open all DSRC packets
wireshark dsrc_trace-*.pcap &

# Or open only CSMA/RSU→Controller packets
wireshark csma_trace-*.pcap &

# Or open both sequentially (Wireshark will merge them)
wireshark dsrc_trace-*.pcap csma_trace-*.pcap &
```

#### Option B: CLI (Command-line, for batch analysis)

```bash
# Export packet list to CSV for further processing
tshark -r dsrc_trace-*.pcap -T fields \
  -e frame.time_relative \
  -e eth.src \
  -e eth.dst \
  -e ip.src \
  -e ip.dst \
  -e frame.len \
  > wireshark_packet_export.csv

# Count total packets
tshark -r dsrc_trace-*.pcap -Y "frame" | wc -l

# Extract only specific protocol (e.g., ARP, IP, UDP)
tshark -r dsrc_trace-*.pcap -Y "arp || ip.version==4" -w filtered_packets.pcap
```

### Step 4: Interpret Wireshark Display

#### Key Columns in Wireshark GUI

| Column | Meaning |
|--------|---------|
| **No.** | Packet sequence number |
| **Time** | Relative simulation time (seconds) |
| **Source** | Sender node MAC/IP address |
| **Destination** | Receiver node MAC/IP address |
| **Protocol** | Layer (ARP, IP, UDP, ICMP, etc.) |
| **Length** | Packet payload size (bytes) |
| **Info** | Protocol-specific details |

#### Expand a Packet to View Custom Tags

1. Click a packet in the list
2. Expand **Ethernet II → Data** in the lower pane
3. Look for custom tag fields:
   - `CustomDataTag1` — topology beacon with position, velocity, timestamp
   - `CustomHeartbeatTag` — liveness heartbeat with claimed_sender, timestamp, is_replayed flag
   - `CustomMetaDataUnicastTag0` — RSU→Controller metadata

### Step 5: Apply Filters to Isolate Attack Events

#### Filter by Simulation Time Window

```
frame.time_relative >= 10 && frame.time_relative <= 25
```

This captures the attack window for TTW (t=10 HELLO, t=20 replay).

#### Filter by Source Node

```
eth.src == "02:00:00:00:00:02"  # node 2 (RSU, if applicable)
```

#### Filter by Broadcast Packets Only

```
eth.dst == "ff:ff:ff:ff:ff:ff"
```

#### Filter by CSMA Port (RSU→Controller)

```
udp.dstport == 7777  # controller's main port
```

#### Combine Filters

```
(frame.time_relative >= 10 && frame.time_relative <= 25) && (udp.dstport == 7777)
```

---

## Specific Analysis for Your Attack Scenarios

### TTW (Topology Time-Warp) Attack

**What to Look For:**
- Topology packets with **older timestamps** arriving **after** newer ones
- Same link reported multiple times with different timestamps
- Timestamps that exceed the 100ms beacon budget (detection threshold)

**Analysis Steps:**

1. **Filter for topology packets:**
   ```
   frame.time_relative >= 10 && frame.time_relative <= 21
   ```

2. **Look for timestamp anomalies in packet details:**
   - Find `CustomDataTag1` fields
   - Compare packet's **internal timestamp** (in the tag) with **frame.time_relative** (when it arrived)
   - Difference > 50ms indicates a replay

3. **Cross-reference with logs:**
   ```bash
   grep "REPLAY" ttw_attack_scenario4.txt
   grep "attack_label=1" pem_event_log.csv
   ```

4. **Example interpretation:**
   ```
   Packet 123: frame.time_relative=20.050s, CustomDataTag1.timestamp=10.100s
   → TTW-S1 detected: old timestamp (10.1s) arriving at new time (20.05s)
   ```

---

### BSHH (Beacon State Heartbeat Hijack) Attack

**What to Look For:**
- Heartbeat packets with **mismatched sender identities**
- Same identity claimed by different source addresses
- Old heartbeats (low timestamp) arriving after newer ones (high timestamp)

**Analysis Steps:**

1. **Filter for heartbeat packets:**
   ```
   frame.time_relative >= 5 && frame.time_relative <= 15
   ```

2. **Examine heartbeat tag fields:**
   - `CustomHeartbeatTag.claimed_sender_id` — whose liveness is claimed (e.g., V1)
   - `CustomHeartbeatTag.physical_sender_id` — who actually transmitted (e.g., V2 in hijack)
   - If these differ → **potential hijack**
   - `CustomHeartbeatTag.is_replayed` — flag set by attacker

3. **Timeline analysis:**
   ```bash
   # Extract heartbeat timestamps
   tshark -r dsrc_trace-*.pcap -Y "CustomHeartbeatTag" -T fields \
     -e frame.time_relative \
     -e CustomHeartbeatTag.claimed_sender_id \
     -e CustomHeartbeatTag.timestamp \
     | sort -k3 -n
   ```

4. **Example interpretation:**
   ```
   Time=5.0s  claimed_sender=V1  tag_timestamp=5.0   is_replayed=0  → legitimate
   Time=10.0s claimed_sender=V1  tag_timestamp=0.0   is_replayed=1  → BSHH attack!
   ```

---

### ME (Multipath Echo) Attack

**What to Look For:**
- Multiple reporters claiming to observe the **same link**
- Reporters that are **geographically far apart** (outside 300m DSRC range)
- Link observations from nodes that should **not have direct sight** of the link endpoints

**Analysis Steps:**

1. **Filter for topology reports from specific nodes:**
   ```
   eth.src == "02:00:00:00:00:03" || eth.src == "02:00:00:00:00:04"  # V3, V4 (echoing)
   ```

2. **Extract link reports:**
   ```bash
   tshark -r dsrc_trace-*.pcap -Y "CustomDataTag1" -T fields \
     -e frame.time_relative \
     -e eth.src \
     -e CustomDataTag1.link_src \
     -e CustomDataTag1.link_dst \
     > me_link_reports.csv
   ```

3. **Identify echo anomalies:**
   - Find duplicate link reports `(V1, V2)` from multiple reporters V3, V4
   - Check positions: if V3 is >300m away from both V1 and V2 → **phantom reporter**
   - Compare with `channel_delivery_analysis.csv` — normal fanout should be ~2–3, not 4–5

4. **Example interpretation:**
   ```
   Link (V1=10, V2=20) reported by V1 at 10.0s    → legitimate reporter
   Link (V1=10, V2=20) reported by V2 at 10.1s    → legitimate reporter
   Link (V1=10, V2=20) reported by V3 at 10.2s    → ECHO: V3 is 450m away → ME-S1!
   Link (V1=10, V2=20) reported by V4 at 10.3s    → ECHO: V4 is 480m away → ME-S1!
   ```

---

## Practical Detection Enhancement

### Cross-Reference Wireshark Exports with PEM Logs

**Workflow:**

1. **Export all packets to CSV:**
   ```bash
   tshark -r dsrc_trace-*.pcap -T fields \
     -e frame.time_relative \
     -e eth.src \
     -e eth.dst \
     -e frame.len \
     -e frame.protocols \
     > wireshark_export.csv
   ```

2. **Export Wireshark timestamps to match PEM event times:**
   ```bash
   tshark -r dsrc_trace-*.pcap -T fields \
     -e frame.time_relative \
     > packet_times.txt

   # Compare with PEM event times
   cut -d, -f1 pem_event_log.csv > pem_times.txt
   comm -23 <(sort packet_times.txt) <(sort pem_times.txt) > unmatched_packets.txt
   ```

3. **Validate detection latency:**
   ```bash
   # Get first attack packet time from Wireshark
   ATTACK_TIME=$(tshark -r dsrc_trace-*.pcap -Y \
     '(CustomDataTag1.is_forged==1)' -T fields \
     -e frame.time_relative | head -1)

   # Get first alert time from PEM
   ALERT_TIME=$(grep "alert_raised=1" pem_event_log.csv | head -1 | cut -d, -f1)

   # Compute detection latency (should be <100ms)
   python3 -c "print(f'Latency: {(float($ALERT_TIME) - float($ATTACK_TIME)) * 1000:.2f} ms')"
   ```

### Automated Packet Analysis Script

**Python script to correlate Wireshark and PEM data:**

```python
#!/usr/bin/env python3
"""
wireshark_pem_correlator.py
Correlates Wireshark packet exports with PEM detection logs
"""

import csv
import sys
from collections import defaultdict

def load_wireshark_csv(filename):
    """Load exported Wireshark packet times"""
    packets = []
    with open(filename) as f:
        for row in csv.DictReader(f):
            packets.append(float(row['frame.time_relative']))
    return sorted(packets)

def load_pem_csv(filename):
    """Load PEM event log with detection times"""
    events = []
    with open(filename) as f:
        for row in csv.DictReader(f):
            if row.get('alert_raised') == '1':
                events.append({
                    'time': float(row['sim_time_s']),
                    'event_type': row['event_type'],
                    'score': float(row['score'])
                })
    return sorted(events, key=lambda x: x['time'])

def find_detection_latency(attack_time, events):
    """Find first alert after attack time"""
    for event in events:
        if event['time'] >= attack_time:
            return (event['time'] - attack_time) * 1000  # convert to ms
    return None

def main():
    wireshark_file = "wireshark_export.csv"
    pem_file = "pem_event_log.csv"
    
    packets = load_wireshark_csv(wireshark_file)
    events = load_pem_csv(pem_file)
    
    print(f"[Wireshark] Total packets: {len(packets)}")
    print(f"[PEM] Alert events: {len(events)}")
    
    if packets and events:
        first_attack_pkt = packets[0]
        latency_ms = find_detection_latency(first_attack_pkt, events)
        
        if latency_ms:
            status = "✓ PASS" if latency_ms < 100 else "✗ FAIL"
            print(f"[Detection Latency] {status}: {latency_ms:.2f} ms")
            print(f"  Attack packet at: {first_attack_pkt:.3f}s")
            print(f"  First alert at:   {events[0]['time']:.3f}s")
        else:
            print("[Detection Latency] ✗ No alert found after attack packet")

if __name__ == '__main__':
    main()
```

**Run it:**
```bash
python3 wireshark_pem_correlator.py
```

### Batch Analysis for Multiple Runs

**Shell script to analyze 5 runs:**

```bash
#!/bin/bash
# analyze_5_runs.sh
# Correlates Wireshark and PEM data across multiple simulation runs

SCENARIO=$1

for RUN in 1 2 3 4 5; do
    echo "=== Run $RUN ==="
    
    # Export Wireshark packets
    tshark -r dsrc_trace-*.pcap -T fields \
      -e frame.time_relative \
      -e eth.src \
      -e CustomDataTag1.timestamp \
      > run_${RUN}_packets.csv
    
    # Correlate with PEM
    python3 wireshark_pem_correlator.py
    
    echo ""
done
```

---

## Quick Reference: Common Wireshark Tasks

### View Packets in Human-Readable Format

```bash
# Print first 50 packets to terminal
tshark -r dsrc_trace-*.pcap -Y "frame" | head -50
```

### Extract Specific Protocol

```bash
# Only IPv4 packets
tshark -r dsrc_trace-*.pcap -Y "ip.version==4" -w ipv4_only.pcap
```

### Count Packets per Source

```bash
# Packet count by sender
tshark -r dsrc_trace-*.pcap -T fields -e eth.src | sort | uniq -c | sort -rn
```

### Generate Statistics

```bash
# IO graph data (packets per 1-second interval)
tshark -r dsrc_trace-*.pcap -q -z io,stat,1
```

### Filter by Attack Window

```bash
# Extract only attack-phase packets (e.g., t=10 to t=25 for TTW)
tshark -r dsrc_trace-*.pcap \
  -Y "(frame.time_relative >= 10 && frame.time_relative <= 25)" \
  -w attack_window.pcap
```

---

## Integration Checklist

Before analyzing your attack scenarios, ensure:

- [ ] Wireshark 3.6+ is installed: `wireshark --version`
- [ ] PCAP tracing is enabled in `routing.cc` (added to `main()` before `Simulator::Run()`)
- [ ] Simulation runs successfully: `./waf --run "scratch/routing ..."`
- [ ] PCAP files are generated: `ls -la dsrc_trace-*.pcap csma_trace-*.pcap`
- [ ] CSV exports work: `tshark -r dsrc_trace-*.pcap -T fields ... > export.csv`
- [ ] PEM logs are generated: `ls -la pem_event_log.csv pem_run_summary.csv`
- [ ] Cross-reference script runs: `python3 wireshark_pem_correlator.py`

---

## Summary

| Task | Tool | Output |
|------|------|--------|
| **Packet inspection** | Wireshark GUI | Interactive visualization |
| **Batch packet analysis** | `tshark` CLI | CSV, filtered PCAP |
| **PEM detection validation** | `pem_event_log.csv` | Detection latency, scores |
| **Attack logs** | `ttw_attack_scenario*.txt` | Timeline of attack steps |
| **Correlation** | Python script | Cross-check packet ↔ detection |
| **Channel analysis** | `channel_delivery_analysis.csv` | Per-channel fanout, PDR |

By combining **Wireshark packet capture**, **PEM event logs**, and **attack logs**, you can completely validate your temporal-echo attack implementation and detection mechanisms.

---

*Document created for SDVN Temporal-Echo Topology Attack Project — Department of EIE, University of Ruhuna*
