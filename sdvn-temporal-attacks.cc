/*
 * SDVN Temporal-Echo Topology Attacks Simulation
 * Implements: TTW, BSHH, and ME attacks with malicious RSU
 * NS-3.35 Implementation
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"
#include "ns3/point-to-point-module.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <iomanip>

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("SDVN-Temporal-Attacks");

// ==================== CONFIGURATION PARAMETERS ====================
enum AttackType {
    NO_ATTACK = 0,
    TTW_ATTACK = 1,      // Topology Time-Warp Attack
    BSHH_ATTACK = 2,     // Beacon State Heartbeat Hijack Attack
    ME_ATTACK = 3        // Multipath Echo Attack
};

// Global simulation parameters
uint32_t nVehicles = 4;           // Number of vehicles (V1, V2, V3, V4)
uint32_t nRSUs = 1;               // Number of RSUs
uint32_t nControllers = 1;        // SDN Controller
double simTime = 30.0;            // Simulation time in seconds
int attackTypeInt = 1;            // Attack type as int for CommandLine (1=TTW, 2=BSHH, 3=ME)
AttackType currentAttack = TTW_ATTACK;  // Attack to simulate (set after parsing)
int maliciousRSUInt = 1;          // 1=malicious RSU, 0=benign (int for CommandLine)
bool maliciousRSU = true;         // RSU is malicious (set after parsing)
uint32_t attackerRSU = 0;         // Which RSU is malicious

// Communication ranges and parameters
double wifiRange = 200.0;         // WiFi communication range (meters)
double vehicleSpeed = 15.0;       // Vehicle speed (m/s)
uint16_t beaconPort = 8001;       // Port for beacon/heartbeat
uint16_t topologyPort = 8002;     // Port for topology updates
uint16_t controllerPort = 9000;   // Controller port

// Attack timing parameters
double attackStartTime = 10.0;    // When attack begins
double linkBreakTime = 15.0;      // When V1-V2 link breaks
double replayTime = 20.0;         // When malicious replay occurs

// ==================== CUSTOM PACKET TAGS ====================

// Tag for Topology Update Messages
class TopologyUpdateTag : public Tag {
public:
    static TypeId GetTypeId(void);
    virtual TypeId GetInstanceTypeId(void) const;
    virtual uint32_t GetSerializedSize(void) const;
    virtual void Serialize(TagBuffer i) const;
    virtual void Deserialize(TagBuffer i);
    virtual void Print(std::ostream &os) const;

    void SetSourceId(uint32_t id) { m_sourceId = id; }
    void SetNeighborId(uint32_t id) { m_neighborId = id; }
    void SetTimestamp(double t) { m_timestamp = t; }
    void SetMalicious(bool mal) { m_isMalicious = mal; }
    void SetForged(bool forged) { m_isForged = forged; }

    uint32_t GetSourceId() const { return m_sourceId; }
    uint32_t GetNeighborId() const { return m_neighborId; }
    double GetTimestamp() const { return m_timestamp; }
    bool IsMalicious() const { return m_isMalicious; }
    bool IsForged() const { return m_isForged; }

private:
    uint32_t m_sourceId;
    uint32_t m_neighborId;
    double m_timestamp;
    bool m_isMalicious;
    bool m_isForged;
};

TypeId TopologyUpdateTag::GetTypeId(void) {
    static TypeId tid = TypeId("ns3::TopologyUpdateTag")
        .SetParent<Tag>()
        .AddConstructor<TopologyUpdateTag>();
    return tid;
}

TypeId TopologyUpdateTag::GetInstanceTypeId(void) const {
    return GetTypeId();
}

uint32_t TopologyUpdateTag::GetSerializedSize(void) const {
    return sizeof(uint32_t) * 2 + sizeof(double) + sizeof(bool) * 2;
}

void TopologyUpdateTag::Serialize(TagBuffer i) const {
    i.WriteU32(m_sourceId);
    i.WriteU32(m_neighborId);
    i.WriteDouble(m_timestamp);
    i.WriteU8(m_isMalicious ? 1 : 0);
    i.WriteU8(m_isForged ? 1 : 0);
}

void TopologyUpdateTag::Deserialize(TagBuffer i) {
    m_sourceId = i.ReadU32();
    m_neighborId = i.ReadU32();
    m_timestamp = i.ReadDouble();
    m_isMalicious = (i.ReadU8() == 1);
    m_isForged = (i.ReadU8() == 1);
}

void TopologyUpdateTag::Print(std::ostream &os) const {
    os << "Topology: V" << m_sourceId << "->V" << m_neighborId 
       << " @t=" << m_timestamp 
       << (m_isMalicious ? " [MALICIOUS]" : "")
       << (m_isForged ? " [FORGED]" : "");
}

NS_OBJECT_ENSURE_REGISTERED(TopologyUpdateTag);

// Tag for Heartbeat/Beacon Messages
class HeartbeatTag : public Tag {
public:
    static TypeId GetTypeId(void);
    virtual TypeId GetInstanceTypeId(void) const;
    virtual uint32_t GetSerializedSize(void) const;
    virtual void Serialize(TagBuffer i) const;
    virtual void Deserialize(TagBuffer i);
    virtual void Print(std::ostream &os) const;

    void SetSenderId(uint32_t id) { m_senderId = id; }
    void SetTimestamp(double t) { m_timestamp = t; }
    void SetIsReplay(bool replay) { m_isReplay = replay; }
    void SetOriginalTimestamp(double t) { m_originalTimestamp = t; }

    uint32_t GetSenderId() const { return m_senderId; }
    double GetTimestamp() const { return m_timestamp; }
    bool IsReplay() const { return m_isReplay; }
    double GetOriginalTimestamp() const { return m_originalTimestamp; }

private:
    uint32_t m_senderId;
    double m_timestamp;
    bool m_isReplay;
    double m_originalTimestamp;
};

TypeId HeartbeatTag::GetTypeId(void) {
    static TypeId tid = TypeId("ns3::HeartbeatTag")
        .SetParent<Tag>()
        .AddConstructor<HeartbeatTag>();
    return tid;
}

TypeId HeartbeatTag::GetInstanceTypeId(void) const {
    return GetTypeId();
}

uint32_t HeartbeatTag::GetSerializedSize(void) const {
    return sizeof(uint32_t) + sizeof(double) * 2 + sizeof(bool);
}

void HeartbeatTag::Serialize(TagBuffer i) const {
    i.WriteU32(m_senderId);
    i.WriteDouble(m_timestamp);
    i.WriteU8(m_isReplay ? 1 : 0);
    i.WriteDouble(m_originalTimestamp);
}

void HeartbeatTag::Deserialize(TagBuffer i) {
    m_senderId = i.ReadU32();
    m_timestamp = i.ReadDouble();
    m_isReplay = (i.ReadU8() == 1);
    m_originalTimestamp = i.ReadDouble();
}

void HeartbeatTag::Print(std::ostream &os) const {
    os << "Heartbeat from V" << m_senderId 
       << " @t=" << m_timestamp
       << (m_isReplay ? " [REPLAY from t=" + to_string(m_originalTimestamp) + "]" : "");
}

NS_OBJECT_ENSURE_REGISTERED(HeartbeatTag);

// ==================== GLOBAL DATA STRUCTURES ====================

// Controller's view of network topology
struct TopologyEntry {
    uint32_t sourceNode;
    uint32_t neighborNode;
    double timestamp;
    bool isActive;
    bool isForged;
};

map<pair<uint32_t, uint32_t>, TopologyEntry> controllerTopology;

// Stored packets for replay attacks (at malicious RSU)
struct StoredPacket {
    Ptr<Packet> packet;
    double originalTimestamp;
    uint32_t sourceId;
    uint32_t neighborId;
};

vector<StoredPacket> storedTopologyUpdates;
vector<StoredPacket> storedHeartbeats;

// Statistics
uint32_t totalBeaconsSent = 0;
uint32_t totalTopologyUpdatesSent = 0;
uint32_t totalMaliciousPackets = 0;
uint32_t totalReplayedPackets = 0;
uint32_t falseLinkDetections = 0;
uint32_t routingErrors = 0;

// Output streams for logging
ofstream logFile;
ofstream topologyLog;
ofstream attackLog;

// ==================== HELPER FUNCTIONS ====================

void LogEvent(string event) {
    double now = Simulator::Now().GetSeconds();
    logFile << fixed << setprecision(3) << now << "s - " << event << endl;
    cout << fixed << setprecision(3) << now << "s - " << event << endl;
}

void LogTopologyUpdate(uint32_t src, uint32_t dst, double timestamp, bool forged) {
    topologyLog << fixed << setprecision(3) 
                << Simulator::Now().GetSeconds() << ","
                << src << "," << dst << "," << timestamp 
                << "," << (forged ? "FORGED" : "LEGITIMATE") << endl;
}

void LogAttack(string attackType, string details) {
    double now = Simulator::Now().GetSeconds();
    attackLog << fixed << setprecision(3) << now << "," 
              << attackType << "," << details << endl;
    totalMaliciousPackets++;
}

// Check if two vehicles are within communication range
bool InRange(Ptr<Node> n1, Ptr<Node> n2, double range) {
    Ptr<MobilityModel> mob1 = n1->GetObject<MobilityModel>();
    Ptr<MobilityModel> mob2 = n2->GetObject<MobilityModel>();
    double distance = mob1->GetDistanceFrom(mob2);
    return distance <= range;
}

// ==================== VEHICLE APPLICATION ====================

class VehicleApplication : public Application {
public:
    VehicleApplication();
    virtual ~VehicleApplication();
    
    void Setup(Ptr<Socket> socket, Ptr<Node> node, uint32_t vehicleId, 
               Address rsuAddress, Address controllerAddress);
    
private:
    virtual void StartApplication(void);
    virtual void StopApplication(void);
    
    void SendBeacon();
    void SendTopologyUpdate(uint32_t neighborId);
    void ReceivePacket(Ptr<Socket> socket);
    void DiscoverNeighbors();
    
    Ptr<Socket> m_socket;
    Ptr<Node> m_node;
    uint32_t m_vehicleId;
    Address m_rsuAddress;
    Address m_controllerAddress;
    EventId m_beaconEvent;
    EventId m_discoveryEvent;
    vector<uint32_t> m_neighbors;
    double m_beaconInterval;
    double m_discoveryInterval;
};

VehicleApplication::VehicleApplication()
    : m_socket(0),
      m_node(0),
      m_vehicleId(0),
      m_beaconInterval(1.0),  // Send beacons every 1 second
      m_discoveryInterval(0.5) // Check neighbors every 0.5 seconds
{
}

VehicleApplication::~VehicleApplication() {
    m_socket = 0;
}

void VehicleApplication::Setup(Ptr<Socket> socket, Ptr<Node> node, 
                               uint32_t vehicleId, Address rsuAddress, 
                               Address controllerAddress) {
    m_socket = socket;
    m_node = node;
    m_vehicleId = vehicleId;
    m_rsuAddress = rsuAddress;
    m_controllerAddress = controllerAddress;
}

void VehicleApplication::StartApplication(void) {
    m_socket->SetRecvCallback(MakeCallback(&VehicleApplication::ReceivePacket, this));
    m_beaconEvent = Simulator::Schedule(Seconds(1.0), 
                                        &VehicleApplication::SendBeacon, this);
    m_discoveryEvent = Simulator::Schedule(Seconds(0.5), 
                                          &VehicleApplication::DiscoverNeighbors, this);
}

void VehicleApplication::StopApplication(void) {
    Simulator::Cancel(m_beaconEvent);
    Simulator::Cancel(m_discoveryEvent);
    m_socket->Close();
}

void VehicleApplication::SendBeacon() {
    // Create beacon packet
    Ptr<Packet> packet = Create<Packet>(100);
    
    HeartbeatTag hbTag;
    hbTag.SetSenderId(m_vehicleId);
    hbTag.SetTimestamp(Simulator::Now().GetSeconds());
    hbTag.SetIsReplay(false);
    hbTag.SetOriginalTimestamp(Simulator::Now().GetSeconds());
    
    packet->AddPacketTag(hbTag);
    
    // Broadcast beacon
    m_socket->SendTo(packet, 0, 
                     InetSocketAddress(Ipv4Address("255.255.255.255"), beaconPort));
    
    totalBeaconsSent++;
    
    LogEvent("V" + to_string(m_vehicleId) + " sent BEACON");
    
    // Schedule next beacon
    m_beaconEvent = Simulator::Schedule(Seconds(m_beaconInterval), 
                                        &VehicleApplication::SendBeacon, this);
}

void VehicleApplication::SendTopologyUpdate(uint32_t neighborId) {
    // Create topology update packet
    Ptr<Packet> packet = Create<Packet>(150);
    
    TopologyUpdateTag topTag;
    topTag.SetSourceId(m_vehicleId);
    topTag.SetNeighborId(neighborId);
    topTag.SetTimestamp(Simulator::Now().GetSeconds());
    topTag.SetMalicious(false);
    topTag.SetForged(false);
    
    packet->AddPacketTag(topTag);
    
    // Send to RSU
    m_socket->SendTo(packet, 0, m_rsuAddress);
    
    totalTopologyUpdatesSent++;
    
    LogEvent("V" + to_string(m_vehicleId) + " sent TOPOLOGY UPDATE: V" + 
             to_string(m_vehicleId) + " sees V" + to_string(neighborId));
}

void VehicleApplication::DiscoverNeighbors() {
    // Get all vehicle nodes from NodeContainer
    NodeContainer allNodes = NodeContainer::GetGlobal();
    vector<uint32_t> currentNeighbors;
    
    for (uint32_t i = 0; i < allNodes.GetN(); i++) {
        Ptr<Node> otherNode = allNodes.Get(i);
        if (otherNode == m_node) continue;
        
        // Check if it's a vehicle node (not RSU or controller)
        if (i >= nVehicles) continue;
        
        if (InRange(m_node, otherNode, wifiRange)) {
            currentNeighbors.push_back(i);
            
            // Check if this is a new neighbor
            if (find(m_neighbors.begin(), m_neighbors.end(), i) == m_neighbors.end()) {
                LogEvent("V" + to_string(m_vehicleId) + " discovered neighbor V" + to_string(i));
                // Send topology update to RSU
                SendTopologyUpdate(i);
            }
        }
    }
    
    // Update neighbors list
    m_neighbors = currentNeighbors;
    
    // Schedule next discovery
    m_discoveryEvent = Simulator::Schedule(Seconds(m_discoveryInterval), 
                                          &VehicleApplication::DiscoverNeighbors, this);
}

void VehicleApplication::ReceivePacket(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;
    
    while ((packet = socket->RecvFrom(from))) {
        // Check for heartbeat tag
        HeartbeatTag hbTag;
        if (packet->PeekPacketTag(hbTag)) {
            uint32_t senderId = hbTag.GetSenderId();
            if (senderId != m_vehicleId) {
                LogEvent("V" + to_string(m_vehicleId) + " received BEACON from V" + 
                        to_string(senderId));
            }
        }
    }
}

// ==================== RSU APPLICATION ====================

class RSUApplication : public Application {
public:
    RSUApplication();
    virtual ~RSUApplication();
    
    void Setup(Ptr<Socket> socket, uint32_t rsuId, Address controllerAddress, 
               bool isMalicious, AttackType attackType);
    
private:
    virtual void StartApplication(void);
    virtual void StopApplication(void);
    
    void ReceivePacket(Ptr<Socket> socket);
    void ForwardToController(Ptr<Packet> packet);
    
    // Attack methods
    void PerformTTWAttack();
    void PerformBSHHAttack();
    void PerformMEAttack();
    
    void StorePacketForReplay(Ptr<Packet> packet);
    void ReplayStoredTopologyUpdate();
    void ReplayStoredHeartbeat();
    void InjectEchoObservations();
    
    Ptr<Socket> m_socket;
    uint32_t m_rsuId;
    Address m_controllerAddress;
    bool m_isMalicious;
    AttackType m_attackType;
    EventId m_attackEvent;
    
    vector<StoredPacket> m_localStoredPackets;
    map<uint32_t, double> m_lastHeartbeatTime;
};

RSUApplication::RSUApplication()
    : m_socket(0),
      m_rsuId(0),
      m_isMalicious(false),
      m_attackType(NO_ATTACK)
{
}

RSUApplication::~RSUApplication() {
    m_socket = 0;
}

void RSUApplication::Setup(Ptr<Socket> socket, uint32_t rsuId, 
                          Address controllerAddress, bool isMalicious, 
                          AttackType attackType) {
    m_socket = socket;
    m_rsuId = rsuId;
    m_controllerAddress = controllerAddress;
    m_isMalicious = isMalicious;
    m_attackType = attackType;
}

void RSUApplication::StartApplication(void) {
    m_socket->SetRecvCallback(MakeCallback(&RSUApplication::ReceivePacket, this));
    
    if (m_isMalicious) {
        // Schedule attack based on type
        switch (m_attackType) {
            case TTW_ATTACK:
                m_attackEvent = Simulator::Schedule(Seconds(replayTime), 
                                                   &RSUApplication::PerformTTWAttack, this);
                LogEvent("RSU" + to_string(m_rsuId) + " configured for TTW ATTACK");
                break;
            case BSHH_ATTACK:
                m_attackEvent = Simulator::Schedule(Seconds(replayTime), 
                                                   &RSUApplication::PerformBSHHAttack, this);
                LogEvent("RSU" + to_string(m_rsuId) + " configured for BSHH ATTACK");
                break;
            case ME_ATTACK:
                m_attackEvent = Simulator::Schedule(Seconds(replayTime), 
                                                   &RSUApplication::PerformMEAttack, this);
                LogEvent("RSU" + to_string(m_rsuId) + " configured for ME ATTACK");
                break;
            default:
                break;
        }
    }
}

void RSUApplication::StopApplication(void) {
    Simulator::Cancel(m_attackEvent);
    m_socket->Close();
}

void RSUApplication::ReceivePacket(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;
    
    while ((packet = socket->RecvFrom(from))) {
        // Make a copy for potential storage
        Ptr<Packet> packetCopy = packet->Copy();
        
        // Check for topology update tag
        TopologyUpdateTag topTag;
        if (packet->PeekPacketTag(topTag)) {
            LogEvent("RSU" + to_string(m_rsuId) + " received TOPOLOGY UPDATE: V" + 
                    to_string(topTag.GetSourceId()) + " sees V" + 
                    to_string(topTag.GetNeighborId()));
            
            // If malicious, store for potential replay
            if (m_isMalicious && Simulator::Now().GetSeconds() < linkBreakTime) {
                StorePacketForReplay(packetCopy);
            }
            
            // Forward to controller (if not under attack yet)
            if (!m_isMalicious || Simulator::Now().GetSeconds() < attackStartTime) {
                ForwardToController(packet);
            }
        }
        
        // Check for heartbeat tag
        HeartbeatTag hbTag;
        if (packet->PeekPacketTag(hbTag)) {
            uint32_t senderId = hbTag.GetSenderId();
            m_lastHeartbeatTime[senderId] = hbTag.GetTimestamp();
            
            LogEvent("RSU" + to_string(m_rsuId) + " received HEARTBEAT from V" + 
                    to_string(senderId));
            
            // If malicious and BSHH attack, store heartbeat
            if (m_isMalicious && m_attackType == BSHH_ATTACK && 
                Simulator::Now().GetSeconds() < attackStartTime) {
                StorePacketForReplay(packetCopy);
            }
            
            // Forward heartbeat summary to controller
            if (!m_isMalicious || Simulator::Now().GetSeconds() < attackStartTime) {
                ForwardToController(packet);
            }
        }
    }
}

void RSUApplication::ForwardToController(Ptr<Packet> packet) {
    m_socket->SendTo(packet, 0, m_controllerAddress);
    LogEvent("RSU" + to_string(m_rsuId) + " forwarded packet to CONTROLLER");
}

void RSUApplication::StorePacketForReplay(Ptr<Packet> packet) {
    StoredPacket stored;
    stored.packet = packet->Copy();
    stored.originalTimestamp = Simulator::Now().GetSeconds();
    
    // Extract source and neighbor IDs
    TopologyUpdateTag topTag;
    if (packet->PeekPacketTag(topTag)) {
        stored.sourceId = topTag.GetSourceId();
        stored.neighborId = topTag.GetNeighborId();
        
        m_localStoredPackets.push_back(stored);
        storedTopologyUpdates.push_back(stored);
        
        LogEvent("RSU" + to_string(m_rsuId) + " STORED topology update for replay: V" + 
                to_string(stored.sourceId) + "->V" + to_string(stored.neighborId) + 
                " @t=" + to_string(stored.originalTimestamp));
    }
    
    HeartbeatTag hbTag;
    if (packet->PeekPacketTag(hbTag)) {
        stored.sourceId = hbTag.GetSenderId();
        stored.neighborId = 0;
        
        m_localStoredPackets.push_back(stored);
        storedHeartbeats.push_back(stored);
        
        LogEvent("RSU" + to_string(m_rsuId) + " STORED heartbeat for replay: V" + 
                to_string(stored.sourceId) + " @t=" + to_string(stored.originalTimestamp));
    }
}

void RSUApplication::PerformTTWAttack() {
    LogEvent("========== TTW ATTACK INITIATED ==========");
    LogAttack("TTW", "Replay attack started");
    
    // Find stored topology updates from before link break
    for (const auto& stored : storedTopologyUpdates) {
        if (stored.originalTimestamp < linkBreakTime) {
            // Create forged packet with current timestamp
            Ptr<Packet> forgedPacket = Create<Packet>(150);
            
            TopologyUpdateTag forgedTag;
            forgedTag.SetSourceId(stored.sourceId);
            forgedTag.SetNeighborId(stored.neighborId);
            forgedTag.SetTimestamp(Simulator::Now().GetSeconds());  // FORGED TIMESTAMP
            forgedTag.SetMalicious(true);
            forgedTag.SetForged(true);
            
            forgedPacket->AddPacketTag(forgedTag);
            
            // Send forged update to controller
            m_socket->SendTo(forgedPacket, 0, m_controllerAddress);
            
            totalReplayedPackets++;
            
            LogEvent("RSU" + to_string(m_rsuId) + " REPLAYED with FORGED TIMESTAMP: V" + 
                    to_string(stored.sourceId) + "->V" + to_string(stored.neighborId) + 
                    " original_t=" + to_string(stored.originalTimestamp) + 
                    " forged_t=" + to_string(Simulator::Now().GetSeconds()));
            
            LogTopologyUpdate(stored.sourceId, stored.neighborId, 
                            Simulator::Now().GetSeconds(), true);
            
            LogAttack("TTW", "Replayed V" + to_string(stored.sourceId) + "->V" + 
                     to_string(stored.neighborId) + " with forged timestamp");
        }
    }
}

void RSUApplication::PerformBSHHAttack() {
    LogEvent("========== BSHH ATTACK INITIATED ==========");
    LogAttack("BSHH", "Heartbeat replay attack started");
    
    // Replay old heartbeats with identity manipulation
    for (const auto& stored : storedHeartbeats) {
        if (stored.originalTimestamp < attackStartTime) {
            // Create replayed heartbeat
            Ptr<Packet> replayPacket = Create<Packet>(100);
            
            HeartbeatTag replayTag;
            replayTag.SetSenderId(stored.sourceId);
            replayTag.SetTimestamp(stored.originalTimestamp);  // OLD TIMESTAMP
            replayTag.SetIsReplay(true);
            replayTag.SetOriginalTimestamp(stored.originalTimestamp);
            
            replayPacket->AddPacketTag(replayTag);
            
            // Send to controller
            m_socket->SendTo(replayPacket, 0, m_controllerAddress);
            
            totalReplayedPackets++;
            
            LogEvent("RSU" + to_string(m_rsuId) + " REPLAYED OLD HEARTBEAT: V" + 
                    to_string(stored.sourceId) + " old_t=" + 
                    to_string(stored.originalTimestamp) + " replay_t=" + 
                    to_string(Simulator::Now().GetSeconds()));
            
            LogAttack("BSHH", "Replayed heartbeat from V" + to_string(stored.sourceId) + 
                     " with old timestamp=" + to_string(stored.originalTimestamp));
        }
    }
    
    // Send conflicting heartbeats
    if (!storedHeartbeats.empty()) {
        auto& stored = storedHeartbeats[0];
        for (int i = 0; i < 3; i++) {
            Ptr<Packet> conflictPacket = Create<Packet>(100);
            
            HeartbeatTag conflictTag;
            conflictTag.SetSenderId(stored.sourceId);
            conflictTag.SetTimestamp(0.0);  // Very old timestamp
            conflictTag.SetIsReplay(true);
            conflictTag.SetOriginalTimestamp(0.0);
            
            conflictPacket->AddPacketTag(conflictTag);
            m_socket->SendTo(conflictPacket, 0, m_controllerAddress);
            
            LogEvent("RSU sent CONFLICTING HEARTBEAT #" + to_string(i+1));
        }
    }
}

void RSUApplication::PerformMEAttack() {
    LogEvent("========== ME ATTACK INITIATED ==========");
    LogAttack("ME", "Multipath Echo attack started");
    
    // Inject echo observations for V1-V2 link reported by V3 and V4
    // This creates false multipath
    
    uint32_t v1 = 0, v2 = 1, v3 = 2, v4 = 3;
    
    // Forged observation: V3 reports seeing V1-V2 link
    Ptr<Packet> echoPacket1 = Create<Packet>(150);
    TopologyUpdateTag echoTag1;
    echoTag1.SetSourceId(v3);
    echoTag1.SetNeighborId(v1);  // V3 falsely reports V1 as neighbor
    echoTag1.SetTimestamp(Simulator::Now().GetSeconds());
    echoTag1.SetMalicious(true);
    echoTag1.SetForged(true);
    echoPacket1->AddPacketTag(echoTag1);
    m_socket->SendTo(echoPacket1, 0, m_controllerAddress);
    
    LogEvent("RSU injected ECHO: V3 falsely reports seeing V1");
    LogAttack("ME", "Echo injection: V3->V1 (false)");
    falseLinkDetections++;
    
    // Forged observation: V3 reports seeing V1-V2 link
    Ptr<Packet> echoPacket2 = Create<Packet>(150);
    TopologyUpdateTag echoTag2;
    echoTag2.SetSourceId(v3);
    echoTag2.SetNeighborId(v2);  // V3 falsely reports V2 as neighbor
    echoTag2.SetTimestamp(Simulator::Now().GetSeconds());
    echoTag2.SetMalicious(true);
    echoTag2.SetForged(true);
    echoPacket2->AddPacketTag(echoTag2);
    m_socket->SendTo(echoPacket2, 0, m_controllerAddress);
    
    LogEvent("RSU injected ECHO: V3 falsely reports seeing V2");
    LogAttack("ME", "Echo injection: V3->V2 (false)");
    falseLinkDetections++;
    
    // Forged observation: V4 reports seeing V1-V2 link
    Ptr<Packet> echoPacket3 = Create<Packet>(150);
    TopologyUpdateTag echoTag3;
    echoTag3.SetSourceId(v4);
    echoTag3.SetNeighborId(v1);  // V4 falsely reports V1 as neighbor
    echoTag3.SetTimestamp(Simulator::Now().GetSeconds());
    echoTag3.SetMalicious(true);
    echoTag3.SetForged(true);
    echoPacket3->AddPacketTag(echoTag3);
    m_socket->SendTo(echoPacket3, 0, m_controllerAddress);
    
    LogEvent("RSU injected ECHO: V4 falsely reports seeing V1");
    LogAttack("ME", "Echo injection: V4->V1 (false)");
    falseLinkDetections++;
    
    // Forged observation: V4 reports seeing V1-V2 link
    Ptr<Packet> echoPacket4 = Create<Packet>(150);
    TopologyUpdateTag echoTag4;
    echoTag4.SetSourceId(v4);
    echoTag4.SetNeighborId(v2);  // V4 falsely reports V2 as neighbor
    echoTag4.SetTimestamp(Simulator::Now().GetSeconds());
    echoTag4.SetMalicious(true);
    echoTag4.SetForged(true);
    echoPacket4->AddPacketTag(echoTag4);
    m_socket->SendTo(echoPacket4, 0, m_controllerAddress);
    
    LogEvent("RSU injected ECHO: V4 falsely reports seeing V2");
    LogAttack("ME", "Echo injection: V4->V2 (false)");
    falseLinkDetections++;
    
    totalReplayedPackets += 4;
}

// ==================== CONTROLLER APPLICATION ====================

class ControllerApplication : public Application {
public:
    ControllerApplication();
    virtual ~ControllerApplication();
    
    void Setup(Ptr<Socket> socket, uint32_t controllerId);
    void PrintTopology();
    void DetectInconsistencies();
    
private:
    virtual void StartApplication(void);
    virtual void StopApplication(void);
    
    void ReceivePacket(Ptr<Socket> socket);
    void ProcessTopologyUpdate(TopologyUpdateTag& tag);
    void ProcessHeartbeat(HeartbeatTag& tag);
    void UpdateRoutingTable();
    
    Ptr<Socket> m_socket;
    uint32_t m_controllerId;
    EventId m_printEvent;
    EventId m_detectEvent;
    
    map<pair<uint32_t, uint32_t>, TopologyEntry> m_topology;
    map<uint32_t, double> m_lastHeartbeat;
    vector<string> m_inferredPaths;
};

ControllerApplication::ControllerApplication()
    : m_socket(0),
      m_controllerId(0)
{
}

ControllerApplication::~ControllerApplication() {
    m_socket = 0;
}

void ControllerApplication::Setup(Ptr<Socket> socket, uint32_t controllerId) {
    m_socket = socket;
    m_controllerId = controllerId;
}

void ControllerApplication::StartApplication(void) {
    m_socket->SetRecvCallback(MakeCallback(&ControllerApplication::ReceivePacket, this));
    
    // Schedule periodic topology printing
    m_printEvent = Simulator::Schedule(Seconds(5.0), 
                                       &ControllerApplication::PrintTopology, this);
    
    // Schedule inconsistency detection
    m_detectEvent = Simulator::Schedule(Seconds(2.0), 
                                        &ControllerApplication::DetectInconsistencies, this);
}

void ControllerApplication::StopApplication(void) {
    Simulator::Cancel(m_printEvent);
    Simulator::Cancel(m_detectEvent);
    m_socket->Close();
}

void ControllerApplication::ReceivePacket(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;
    
    while ((packet = socket->RecvFrom(from))) {
        // Check for topology update
        TopologyUpdateTag topTag;
        if (packet->PeekPacketTag(topTag)) {
            ProcessTopologyUpdate(topTag);
        }
        
        // Check for heartbeat
        HeartbeatTag hbTag;
        if (packet->PeekPacketTag(hbTag)) {
            ProcessHeartbeat(hbTag);
        }
    }
}

void ControllerApplication::ProcessTopologyUpdate(TopologyUpdateTag& tag) {
    uint32_t src = tag.GetSourceId();
    uint32_t dst = tag.GetNeighborId();
    double timestamp = tag.GetTimestamp();
    bool forged = tag.IsForged();
    
    LogEvent("CONTROLLER received TOPOLOGY UPDATE: V" + to_string(src) + 
            "->V" + to_string(dst) + " @t=" + to_string(timestamp) + 
            (forged ? " [FORGED]" : ""));
    
    auto key = make_pair(src, dst);
    
    // Update or add entry
    TopologyEntry entry;
    entry.sourceNode = src;
    entry.neighborNode = dst;
    entry.timestamp = timestamp;
    entry.isActive = true;
    entry.isForged = forged;
    
    m_topology[key] = entry;
    controllerTopology[key] = entry;
    
    if (forged) {
        falseLinkDetections++;
    }
    
    // Update routing table
    UpdateRoutingTable();
}

void ControllerApplication::ProcessHeartbeat(HeartbeatTag& tag) {
    uint32_t senderId = tag.GetSenderId();
    double timestamp = tag.GetTimestamp();
    bool isReplay = tag.IsReplay();
    
    LogEvent("CONTROLLER received HEARTBEAT: V" + to_string(senderId) + 
            " @t=" + to_string(timestamp) + (isReplay ? " [REPLAY]" : ""));
    
    // Check for timestamp inconsistencies
    if (m_lastHeartbeat.find(senderId) != m_lastHeartbeat.end()) {
        double lastTime = m_lastHeartbeat[senderId];
        if (timestamp < lastTime) {
            LogEvent("CONTROLLER detected TIMESTAMP INCONSISTENCY: V" + 
                    to_string(senderId) + " old=" + to_string(timestamp) + 
                    " current=" + to_string(lastTime));
            routingErrors++;
        }
    }
    
    m_lastHeartbeat[senderId] = max(m_lastHeartbeat[senderId], timestamp);
}

void ControllerApplication::UpdateRoutingTable() {
    // Simplified routing table update
    // In a real implementation, this would compute shortest paths
    LogEvent("CONTROLLER updating routing table based on topology");
    
    // For ME attack, infer false multipaths
    if (currentAttack == ME_ATTACK && Simulator::Now().GetSeconds() > replayTime) {
        m_inferredPaths.clear();
        m_inferredPaths.push_back("V0->V1 (real)");
        m_inferredPaths.push_back("V0->V2->V1 (false)");
        m_inferredPaths.push_back("V0->V3->V1 (false)");
        m_inferredPaths.push_back("V0->V3->V2->V1 (false)");
        
        LogEvent("CONTROLLER inferred FALSE MULTIPATHS due to echo injection");
        routingErrors++;
    }
}

void ControllerApplication::PrintTopology() {
    LogEvent("========== CONTROLLER TOPOLOGY VIEW ==========");
    
    if (m_topology.empty()) {
        LogEvent("  No topology information available");
    } else {
        for (const auto& entry : m_topology) {
            LogEvent("  V" + to_string(entry.second.sourceNode) + " -> V" + 
                    to_string(entry.second.neighborNode) + " @t=" + 
                    to_string(entry.second.timestamp) + 
                    (entry.second.isForged ? " [FORGED]" : " [LEGITIMATE]") +
                    (entry.second.isActive ? " [ACTIVE]" : " [INACTIVE]"));
        }
    }
    
    if (!m_inferredPaths.empty()) {
        LogEvent("  Inferred Paths:");
        for (const auto& path : m_inferredPaths) {
            LogEvent("    " + path);
        }
    }
    
    LogEvent("=============================================");
    
    // Schedule next print
    m_printEvent = Simulator::Schedule(Seconds(5.0), 
                                       &ControllerApplication::PrintTopology, this);
}

void ControllerApplication::DetectInconsistencies() {
    // Check for stale links
    double currentTime = Simulator::Now().GetSeconds();
    
    for (auto& entry : m_topology) {
        double linkAge = currentTime - entry.second.timestamp;
        if (linkAge > 5.0 && entry.second.isActive) {
            LogEvent("CONTROLLER detected STALE LINK: V" + 
                    to_string(entry.second.sourceNode) + "->V" + 
                    to_string(entry.second.neighborNode) + " age=" + 
                    to_string(linkAge) + "s");
            routingErrors++;
        }
    }
    
    // Schedule next detection
    m_detectEvent = Simulator::Schedule(Seconds(2.0), 
                                        &ControllerApplication::DetectInconsistencies, this);
}

// ==================== MOBILITY CONFIGURATION ====================

// Called by Simulator::Schedule — moves V1 and V2 out of range to simulate link break
static void BreakV1V2Link(Ptr<MobilityModel> mob1, Ptr<MobilityModel> mob2)
{
    mob1->SetPosition(Vector(50.0,  50.0, 0.0));
    mob2->SetPosition(Vector(500.0, 50.0, 0.0));   // Far beyond WiFi range
    LogEvent("========== V1 and V2 MOVED OUT OF RANGE ==========");
}

void ConfigureVehicleMobility(NodeContainer vehicles) {
    MobilityHelper mobility;
    
    // V1 and V2 start close together, then move apart after linkBreakTime
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
    positionAlloc->Add(Vector(50.0,  50.0, 0.0));   // V0 (V1)
    positionAlloc->Add(Vector(100.0, 50.0, 0.0));   // V1 (V2)
    positionAlloc->Add(Vector(300.0, 50.0, 0.0));   // V2 (V3)
    positionAlloc->Add(Vector(350.0, 50.0, 0.0));   // V3 (V4)
    
    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(vehicles);
    
    // Schedule the link break using a regular function (NS-3 doesn't support lambdas here)
    Ptr<MobilityModel> mob1 = vehicles.Get(0)->GetObject<MobilityModel>();
    Ptr<MobilityModel> mob2 = vehicles.Get(1)->GetObject<MobilityModel>();
    Simulator::Schedule(Seconds(linkBreakTime), &BreakV1V2Link, mob1, mob2);
}

// ==================== MAIN SIMULATION ====================

void PrintSimulationStatistics() {
    cout << "\n=========================================" << endl;
    cout << "   SIMULATION STATISTICS" << endl;
    cout << "=========================================" << endl;
    cout << "Attack Type: ";
    switch (currentAttack) {
        case TTW_ATTACK: cout << "TTW (Topology Time-Warp)" << endl; break;
        case BSHH_ATTACK: cout << "BSHH (Beacon State Heartbeat Hijack)" << endl; break;
        case ME_ATTACK: cout << "ME (Multipath Echo)" << endl; break;
        default: cout << "None" << endl; break;
    }
    cout << "Malicious RSU: " << (maliciousRSU ? "Yes" : "No") << endl;
    cout << "-----------------------------------------" << endl;
    cout << "Total Beacons Sent: " << totalBeaconsSent << endl;
    cout << "Total Topology Updates Sent: " << totalTopologyUpdatesSent << endl;
    cout << "Total Malicious Packets: " << totalMaliciousPackets << endl;
    cout << "Total Replayed Packets: " << totalReplayedPackets << endl;
    cout << "False Link Detections: " << falseLinkDetections << endl;
    cout << "Routing Errors: " << routingErrors << endl;
    cout << "=========================================" << endl;
}

int main(int argc, char *argv[]) {
    // Parse command line arguments
    // NS-3 CommandLine cannot parse custom enum or bool types directly.
    // Use int variables, then cast to the proper types after parsing.
    CommandLine cmd;
    cmd.AddValue("nVehicles",    "Number of vehicles",                     nVehicles);
    cmd.AddValue("simTime",      "Simulation time (s)",                    simTime);
    cmd.AddValue("attack",       "Attack type: 0=None 1=TTW 2=BSHH 3=ME", attackTypeInt);
    cmd.AddValue("maliciousRSU", "Malicious RSU: 1=yes 0=no",              maliciousRSUInt);
    cmd.Parse(argc, argv);

    // Cast int values to proper types after parsing
    currentAttack = static_cast<AttackType>(attackTypeInt);
    maliciousRSU  = (maliciousRSUInt != 0);
    
    // Enable logging
    LogComponentEnable("SDVN-Temporal-Attacks", LOG_LEVEL_INFO);
    
    // Open log files
    logFile.open("sdvn-simulation.log");
    topologyLog.open("topology-updates.csv");
    attackLog.open("attack-events.csv");
    
    topologyLog << "Time,Source,Neighbor,Timestamp,Type" << endl;
    attackLog << "Time,AttackType,Details" << endl;
    
    cout << "\n=========================================" << endl;
    cout << "  SDVN Temporal-Echo Topology Attacks" << endl;
    cout << "=========================================" << endl;
    cout << "Simulating: ";
    switch (currentAttack) {
        case TTW_ATTACK: cout << "TTW Attack" << endl; break;
        case BSHH_ATTACK: cout << "BSHH Attack" << endl; break;
        case ME_ATTACK: cout << "ME Attack" << endl; break;
        default: cout << "No Attack" << endl; break;
    }
    cout << "Vehicles: " << nVehicles << endl;
    cout << "RSUs: " << nRSUs << endl;
    cout << "Simulation Time: " << simTime << "s" << endl;
    cout << "=========================================" << endl;
    
    // Create nodes
    NodeContainer vehicleNodes;
    vehicleNodes.Create(nVehicles);
    
    NodeContainer rsuNodes;
    rsuNodes.Create(nRSUs);
    
    NodeContainer controllerNodes;
    controllerNodes.Create(nControllers);
    
    // Configure WiFi for V2V and V2I communication
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211p);
    
    YansWifiPhyHelper wifiPhy;
    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::RangePropagationLossModel", 
                                   "MaxRange", DoubleValue(wifiRange));
    wifiPhy.SetChannel(wifiChannel.Create());
    
    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");
    
    // Install WiFi on vehicles and RSUs
    NetDeviceContainer vehicleDevices = wifi.Install(wifiPhy, wifiMac, vehicleNodes);
    NetDeviceContainer rsuDevices = wifi.Install(wifiPhy, wifiMac, rsuNodes);
    
    // Install Internet stack
    InternetStackHelper internet;
    internet.Install(vehicleNodes);
    internet.Install(rsuNodes);
    internet.Install(controllerNodes);
    
    // Assign IP addresses
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer vehicleInterfaces = ipv4.Assign(vehicleDevices);
    Ipv4InterfaceContainer rsuInterfaces = ipv4.Assign(rsuDevices);
    
    ipv4.SetBase("10.1.2.0", "255.255.255.0");
    // For controller, we need a device - use point-to-point to RSU
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));
    
    NetDeviceContainer p2pDevices = p2p.Install(rsuNodes.Get(0), controllerNodes.Get(0));
    Ipv4InterfaceContainer controllerInterfaces = ipv4.Assign(p2pDevices);
    
    // Configure mobility
    ConfigureVehicleMobility(vehicleNodes);
    
    // RSU mobility (stationary)
    MobilityHelper rsuMobility;
    Ptr<ListPositionAllocator> rsuPositionAlloc = CreateObject<ListPositionAllocator>();
    rsuPositionAlloc->Add(Vector(200.0, 100.0, 0.0));  // RSU position
    rsuMobility.SetPositionAllocator(rsuPositionAlloc);
    rsuMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    rsuMobility.Install(rsuNodes);
    
    // Controller mobility (stationary)
    MobilityHelper controllerMobility;
    Ptr<ListPositionAllocator> controllerPositionAlloc = CreateObject<ListPositionAllocator>();
    controllerPositionAlloc->Add(Vector(200.0, 200.0, 0.0));
    controllerMobility.SetPositionAllocator(controllerPositionAlloc);
    controllerMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    controllerMobility.Install(controllerNodes);
    
    // Setup applications
    
    // Vehicle applications
    for (uint32_t i = 0; i < nVehicles; i++) {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        Ptr<Socket> vehicleSocket = Socket::CreateSocket(vehicleNodes.Get(i), tid);
        vehicleSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), beaconPort));
        vehicleSocket->SetAllowBroadcast(true);
        
        Ptr<VehicleApplication> vehicleApp = CreateObject<VehicleApplication>();
        InetSocketAddress rsuAddr(rsuInterfaces.GetAddress(0), topologyPort);
        InetSocketAddress controllerAddr(controllerInterfaces.GetAddress(1), controllerPort);
        
        vehicleApp->Setup(vehicleSocket, vehicleNodes.Get(i), i, rsuAddr, controllerAddr);
        vehicleNodes.Get(i)->AddApplication(vehicleApp);
        vehicleApp->SetStartTime(Seconds(1.0));
        vehicleApp->SetStopTime(Seconds(simTime));
    }
    
    // RSU application
    for (uint32_t i = 0; i < nRSUs; i++) {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        Ptr<Socket> rsuSocket = Socket::CreateSocket(rsuNodes.Get(i), tid);
        rsuSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), topologyPort));
        rsuSocket->SetAllowBroadcast(true);
        
        Ptr<RSUApplication> rsuApp = CreateObject<RSUApplication>();
        InetSocketAddress controllerAddr(controllerInterfaces.GetAddress(1), controllerPort);
        
        bool isMalicious = (maliciousRSU && i == attackerRSU);
        rsuApp->Setup(rsuSocket, i, controllerAddr, isMalicious, currentAttack);
        rsuNodes.Get(i)->AddApplication(rsuApp);
        rsuApp->SetStartTime(Seconds(0.5));
        rsuApp->SetStopTime(Seconds(simTime));
    }
    
    // Controller application
    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    Ptr<Socket> controllerSocket = Socket::CreateSocket(controllerNodes.Get(0), tid);
    controllerSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), controllerPort));
    
    Ptr<ControllerApplication> controllerApp = CreateObject<ControllerApplication>();
    controllerApp->Setup(controllerSocket, 0);
    controllerNodes.Get(0)->AddApplication(controllerApp);
    controllerApp->SetStartTime(Seconds(0.0));
    controllerApp->SetStopTime(Seconds(simTime));
    
    // Enable pcap tracing
    wifiPhy.EnablePcapAll("sdvn-attack");
    
    // Setup animation
    AnimationInterface anim("sdvn-attack-animation.xml");
    
    // Color nodes
    for (uint32_t i = 0; i < nVehicles; i++) {
        anim.UpdateNodeColor(vehicleNodes.Get(i), 0, 255, 0);  // Green for vehicles
        anim.UpdateNodeSize(i, 10.0, 10.0);
        anim.UpdateNodeDescription(vehicleNodes.Get(i), "V" + to_string(i));
    }
    
    for (uint32_t i = 0; i < nRSUs; i++) {
        if (maliciousRSU && i == attackerRSU) {
            anim.UpdateNodeColor(rsuNodes.Get(i), 255, 0, 0);  // Red for malicious RSU
        } else {
            anim.UpdateNodeColor(rsuNodes.Get(i), 255, 255, 0);  // Yellow for RSU
        }
        anim.UpdateNodeSize(nVehicles + i, 15.0, 15.0);
        anim.UpdateNodeDescription(rsuNodes.Get(i), "RSU" + to_string(i));
    }
    
    for (uint32_t i = 0; i < nControllers; i++) {
        anim.UpdateNodeColor(controllerNodes.Get(i), 0, 0, 255);  // Blue for controller
        anim.UpdateNodeSize(nVehicles + nRSUs + i, 20.0, 20.0);
        anim.UpdateNodeDescription(controllerNodes.Get(i), "Controller");
    }
    
    // Run simulation
    Simulator::Stop(Seconds(simTime));
    
    LogEvent("========== SIMULATION STARTED ==========");
    
    Simulator::Run();
    
    LogEvent("========== SIMULATION ENDED ==========");
    
    // Print statistics
    PrintSimulationStatistics();
    
    // Close log files
    logFile.close();
    topologyLog.close();
    attackLog.close();
    
    Simulator::Destroy();
    
    cout << "\nLog files generated:" << endl;
    cout << "  - sdvn-simulation.log" << endl;
    cout << "  - topology-updates.csv" << endl;
    cout << "  - attack-events.csv" << endl;
    cout << "  - sdvn-attack-animation.xml" << endl;
    cout << "\nSimulation completed successfully!" << endl;
    
    return 0;
}