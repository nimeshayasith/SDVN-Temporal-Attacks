# SUMO OSM Map Generation — Progress Log

**Project:** SDVN Temporal-Echo Topology Attack — FYP, University of Ruhuna
**Date:** 2026-06-08
**Working directory:** `~/sumo_maps/`

---

## Step 1 — Download OSM Maps ✅ COMPLETE

### Urban (`urban.osm`)
- **Method:** Downloaded via Overpass API (`overpass-api.de/api/map`)
- **Bbox:** `79.843,6.912,79.865,6.935` (Colombo Fort / Pettah — dense city centre)
- **Result:** ✅ Valid OSM file, ~1.1 MB

### Rural (`rural.osm`)
- **First attempt:** `overpass-api.de/api/map?bbox=79.800,6.870,79.860,6.920`
  - **Failed:** Server returned HTTP 406 Not Acceptable (HTML error page, not OSM XML)
- **Fix:** Switched to official OSM API: `api.openstreetmap.org/api/0.6/map`
- **Working command:**
  ```bash
  curl -o rural.osm "https://api.openstreetmap.org/api/0.6/map?bbox=79.800,6.870,79.860,6.920"
  ```
- **Bbox:** `79.800,6.870,79.860,6.920` (Outer Colombo / Kelaniya area)
- **Result:** ✅ Valid OSM file, ~6.0 MB

### Highway (`highway.osm`)
- **First attempt:** Bbox `80.000,6.030,80.100,6.100` → empty file (no road data at that location)
- **Second attempt:** Bbox `79.950,6.750,80.100,6.850` → OSM API error "too many nodes (limit 50000)" — bbox too large
- **Third attempt (success):** Smaller bbox targeting Gelanigama area of Southern Expressway (E01)
  ```bash
  curl -o highway.osm "https://api.openstreetmap.org/api/0.6/map?bbox=80.020,6.800,80.060,6.840"
  ```
- **Bbox:** `80.020,6.800,80.060,6.840` (~4.5 km × 4.5 km slice of Southern Expressway)
- **Result:** ✅ Valid OSM file, ~2.6 MB

> **Lesson learned:** Always use `api.openstreetmap.org/api/0.6/map` instead of `overpass-api.de/api/map`.
> Keep highway bbox under ~0.04° × 0.04° to stay under the 50,000 node limit.

---

## Step 2 — Convert OSM to SUMO Network (`netconvert`) ✅ COMPLETE

### Urban → `urban.net.xml` ✅

```bash
netconvert \
  --osm-files urban.osm \
  --output-file urban.net.xml \
  --geometry.remove \
  --roundabouts.guess \
  --ramps.guess \
  --junctions.join \
  --tls.guess-signals \
  --tls.discard-simple \
  --keep-edges.by-vclass passenger \
  --remove-edges.isolated \
  --no-turnarounds.except-deadend \
  --type-files $SUMO_HOME/data/typemap/osmNetconvert.typ.xml
```

- **Result:** `Success.` — warnings about sharp turns, junction merging, uncontrolled traffic lights are normal for real OSM data

### Rural → `rural.net.xml` ✅

```bash
netconvert \
  --osm-files rural.osm \
  --output-file rural.net.xml \
  --geometry.remove \
  --ramps.guess \
  --keep-edges.by-vclass passenger \
  --remove-edges.isolated \
  --type-files $SUMO_HOME/data/typemap/osmNetconvert.typ.xml
```

### Highway → `highway.net.xml` ✅

```bash
netconvert \
  --osm-files highway.osm \
  --output-file highway.net.xml \
  --geometry.remove \
  --ramps.guess \
  --keep-edges.by-vclass passenger \
  --remove-edges.isolated \
  --type-files $SUMO_HOME/data/typemap/osmNetconvert.typ.xml
```

---

## Step 3 — Generate Vehicle Trips ✅ COMPLETE

Trips generated with `randomTrips.py` for all three networks (no errors):

```bash
python3 $SUMO_HOME/tools/randomTrips.py -n urban.net.xml   -o urban_trips.xml   --begin 0 --end 120 -p 1.0 --vehicle-class passenger --min-distance 200  --fringe-factor 10  --seed 42
python3 $SUMO_HOME/tools/randomTrips.py -n rural.net.xml   -o rural_trips.xml   --begin 0 --end 120 -p 2.0 --vehicle-class passenger --min-distance 500  --fringe-factor 10  --seed 42
python3 $SUMO_HOME/tools/randomTrips.py -n highway.net.xml -o highway_trips.xml --begin 0 --end 120 -p 3.0 --vehicle-class passenger --min-distance 1000 --fringe-factor 100 --seed 42
```

Routes computed with `duarouter`:

```bash
duarouter -n urban.net.xml   --route-files urban_trips.xml   -o urban_routes.xml   --ignore-errors --no-warnings
duarouter -n rural.net.xml   --route-files rural_trips.xml   -o rural_routes.xml   --ignore-errors --no-warnings
duarouter -n highway.net.xml --route-files highway_trips.xml -o highway_routes.xml --ignore-errors --no-warnings
```

> **Note:** `duarouter` flag is `--route-files`, not `-t` (deprecated) and not `--vtype-files` (does not exist).
> The vtype/maxSpeed constraint is only needed in the SUMO config `additional-files`, not in route computation.

---

## Step 4+5 — Run SUMO and Export `.tcl` Traces

### Batch scripts (in `~/sumo_maps/`)

Three scripts were created and fixed. Key fix: removed `--vtype-files` from `duarouter` call
(flag does not exist — vtype only goes into the SUMO `.sumocfg` as `additional-files`).

| Script | Speeds | Output prefix |
|--------|--------|---------------|
| `generate_urban_traces.sh` | 0,10,20,30,40,50,60 | `mobility_urban_*.tcl` |
| `generate_rural_traces.sh` | 0,10,20,30,40,50,60,70,80,90,100 | `mobility_rural_*.tcl` |
| `generate_highway_traces.sh` | 0,10,30,50,70,90,110,130,150,170,190,210,230,250 | `mobility_autobahn_*.tcl` |

Run order:
```bash
chmod +x ~/sumo_maps/generate_urban_traces.sh
chmod +x ~/sumo_maps/generate_rural_traces.sh
chmod +x ~/sumo_maps/generate_highway_traces.sh

./generate_urban_traces.sh
./generate_rural_traces.sh
./generate_highway_traces.sh
```

### Urban traces ✅ COMPLETE

All 7 speed variants generated successfully:

| File | Size | Lines |
|------|------|-------|
| `mobility_urban_0.tcl`  | 3.5 MB | 66,025 |
| `mobility_urban_10.tcl` | 3.5 MB | 66,025 |
| `mobility_urban_20.tcl` | 3.5 MB | 66,025 |
| `mobility_urban_30.tcl` | 3.5 MB | 66,025 |
| `mobility_urban_40.tcl` | 3.5 MB | 66,025 |
| `mobility_urban_50.tcl` | 3.5 MB | 66,025 |
| `mobility_urban_60.tcl` | 3.5 MB | 66,025 |

SUMO reported: 109 vehicles total, 106 active at end of 120s simulation.

### Rural traces — IN PROGRESS / PENDING

Run: `./generate_rural_traces.sh`

### Highway traces — PENDING

Run: `./generate_highway_traces.sh`

---

## Current File Status

| File | Status |
|------|--------|
| `urban.osm` | ✅ |
| `rural.osm` | ✅ |
| `highway.osm` | ✅ |
| `urban.net.xml` | ✅ |
| `rural.net.xml` | ✅ |
| `highway.net.xml` | ✅ |
| `mobility_urban_0..60.tcl` (7 files) | ✅ |
| `mobility_rural_0..100.tcl` (11 files) | ⏳ pending |
| `mobility_autobahn_0..250.tcl` (14 files) | ⏳ pending |

---

## Next Steps After All Traces Are Generated

### 1. Verify bounding boxes (optional but recommended)

Save `check_bbox.py` from Section 5 of `realworld_map_mobility_guide.md` and run:

```bash
python3 check_bbox.py urban.net.xml
python3 check_bbox.py rural.net.xml
python3 check_bbox.py highway.net.xml
```

Expected sizes:

| Network | X width | Y height |
|---------|---------|----------|
| Urban   | ~1500 m | ~1500 m  |
| Rural   | ~7000 m | ~6500 m  |
| Highway | ~4000 m | ~7500 m  |

> Highway may be smaller than expected (we used a smaller bbox). If so, run
> `rsu_placement_check.py` (Section 15 of guide) to verify RSU grid still fits.

### 2. Uncomment 2 lines in `routing.cc` (Step 6 of guide)

Find and uncomment in `routing.cc`:

```cpp
// Line ~143438 — uncomment this:
Ns2MobilityHelper vehicle_mobility = Ns2MobilityHelper(trace_file);

// Line ~143449 — uncomment this:
vehicle_mobility.Install(Vehicle_Nodes.Begin(), Vehicle_Nodes.End());
```

> Only uncomment the `Ns2MobilityHelper` lines — do NOT touch `MobilityHelper vehicle_mobility2`.

### 3. Build and run NS-3 (Step 7 of guide)

```bash
cd ~/ns-allinone-3.35/ns-3.35
./waf build

# Test: urban 30 km/h, no attack
./waf --run "scratch/routing \
    --mobility_scenario=0 \
    --maxspeed=30 \
    --N_Vehicles=22 --N_RSUs=7 \
    --simTime=120 \
    --attack_scenario=0 \
    --routing_test=false"
```

Check output:
```bash
ls -lh results/centralized_mobility_urban_30.csv
head -3 scratch/delay_training_data.csv
```

---

*Log maintained alongside `realworld_map_mobility_guide.md` — update as each step completes.*

---

## PEM Event Log Enhancement — `channel_id` Column ✅ COMPLETE

**Date:** 2026-06-09
**Commit:** `bb8f18c` on branch `sumo_implementation`
**File changed:** `routing.cc`

---

### What was added

A new column `channel_id` was appended as the final field in `pem_event_log.csv`.

| channel_id value | Meaning |
|---|---|
| `178` | DSRC 802.11p Channel 178 (CCH — Control Channel). Used for all direct V2V transmissions. |
| `0` | CSMA Ethernet (wired). Used when an RSU forwards a packet to the controller over the LAN. |
| `9999` | No radio channel — controller-internal operation. Used when the malicious controller poisons its own routing table in memory without transmitting any packet. |

---

### Why this change was needed

The TGNN (Transfer-learned Graph Neural Network) model needs to distinguish between three fundamentally different attack transmission paths:

1. **V2V over the air (DSRC)** — A malicious vehicle forges a packet and broadcasts it on the 5.9 GHz radio. This leaves a physical radio trace (RSSI, fanout anomalies).
2. **RSU→Controller over wire (CSMA)** — A malicious RSU injects a forged entry into the aggregated update it sends over Ethernet to the controller. There is no V2V radio anomaly — the attack is hidden inside a legitimate-looking wired packet.
3. **Controller-internal (no channel)** — A malicious controller rewrites its own topology or liveness table directly in software. No packet is sent anywhere. The attack is invisible to all radio monitors.

Without `channel_id`, the TGNN would see identical event records for an RSU attack and a vehicle attack — the only difference is the `physical_sender_id`. With `channel_id`, the model has a direct structural feature that encodes *how* the attack was delivered, which is critical for cross-scenario generalisation (transfer learning between attack families).

---

### Where in the code

**Struct field** (`PemEvent`, line ~520):
```cpp
int channel_id;  // 172/174/176/178/180/182/184=DSRC channel, 0=CSMA, 9999=controller-internal
```

**Function signatures** (forward declarations ~line 748 and definitions ~line 1446, 1484):
```cpp
static void PemEmitEvent(..., bool attackLabel, int channelId = 178);
static void PemEmitHeartbeatEvent(..., bool attackLabel, int channelId = 178);
```
Default is `178` (DSRC CCH) — vehicle-to-vehicle attacks require no change at their call sites.

**CSV output** — header now ends with `rssi_reporter_dbm,channel_id`, row writer appends `event.channel_id`.

**Explicit overrides at attack call sites:**

| Scenario family | Attacker type | Call site change |
|---|---|---|
| TTW-S2, BSHH-S2, ME-S2 | Malicious RSU | Pass `channelId = 0` (CSMA wired) |
| TTW-S4 legit phase, ME-S2/S4 legit phase | RSU relay | Pass `channelId = 0` (RSU-relayed observation) |
| TTW-S3, TTW-S4, BSHH-S3, BSHH-S4, ME-S3, ME-S4 | Malicious controller | Pass `channelId = 9999` (no transmission) |

---

### Verification

After the change, three representative scenarios were checked:

```
TTW-S1 attack row:  ...,attack_label=1,...,channel_id=178   ← DSRC V2V ✓
TTW-S2 attack row:  ...,attack_label=1,...,channel_id=0     ← CSMA RSU ✓
TTW-S3 attack row:  ...,attack_label=1,...,channel_id=9999  ← controller-internal ✓
```

All 12 scenarios regenerated. PEM detection metrics unchanged: **mcc=1.0, auroc=1.0, fp=0, fn=0** for all 12 attack scenarios.

---

### Why `channel_id=9999` for BSHH-S3 / BSHH-S4 heartbeat attack rows

A reader may notice that BSHH-S3 (Malicious Controller, No RSU) heartbeat attack events show both `physical_sender_id=9999` and `channel_id=9999`. This is correct and intentional.

In BSHH-S3/S4, the controller does **not** broadcast a heartbeat — it directly overwrites `bshh_controller_liveness_table[victim_id]` with a stale `HeartbeatPacket` struct in memory. The `9999` sentinel in `physical_sender_id` is already used throughout the code to mean "the controller itself, not a real node." The matching `channel_id=9999` makes the same statement at the transport layer: *this event has no channel because no packet was ever sent*.

This is the correct threat model for a compromised controller: it is both the source of the forged data and the consumer of that data, with no external communication required.

---

### Note on `rssi_reporter_dbm = -9999`

Heartbeat events (all BSHH scenarios, both legitimate and attack) show `rssi_reporter_dbm = -9999`. This is the `PEM_SIGNAL_PLACEHOLDER` constant — heartbeats are plain in-memory struct operations in the simulation, not 802.11p frames, so no RSSI measurement exists. This is separate from `channel_id` and is the same placeholder used before this change.

---
