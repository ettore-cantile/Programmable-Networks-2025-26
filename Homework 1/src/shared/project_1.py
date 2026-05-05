import time
from datetime import datetime, timezone, timedelta
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.util import dpid_to_str

# Initialize the central logger for terminal output
log = core.getLogger()

class MLController(object):
    def __init__(self, known_collectors, link_capacity):
        # Register to receive OpenFlow events from switches
        core.openflow.addListeners(self)
        
        # Intercept the Discovery module to build the network graph dynamically
        def _handle_core_ComponentRegistered(event):
            if event.name == "openflow_discovery":
                event.component.addListeners(self)
        core.addListenerByName("ComponentRegistered", _handle_core_ComponentRegistered)
        
        # Dictionaries to track ML training sessions and worker statistics
        self.training_sessions = {}
        self.traffic_stats = {}
        
        # Network graph structures: Adjacency list and dynamic host locations
        self.adjacency = {}       
        self.host_locations = {}  
        
        # --- VOLUME-AWARE LOAD BALANCING STATE ---
        # Tracks the exact sum of Bytes (D_v) logically allocated to each physical link
        self.link_allocated_bytes = {} 
        # Base capacity assigned to all discovered links (C_l)
        self.DEFAULT_LINK_CAPACITY = int(link_capacity)
        self.link_max_capacity = {}
        
        # Maps a specific Worker IP to a chosen path to strictly prevent TCP Reordering
        self.assigned_paths = {}    
        
        # Initialize data structures for dynamically provided collectors
        for collector in known_collectors:
            self.training_sessions[collector] = set()
            self.traffic_stats[collector] = {}

    def _handle_LinkEvent(self, event):
        """
        Dynamically builds the network graph.
        """
        l = event.link
        if l.dpid1 not in self.adjacency:
            self.adjacency[l.dpid1] = {}
            
        if event.added:
            # Add edge to adjacency list
            self.adjacency[l.dpid1][l.dpid2] = l.port1
            if (l.dpid1, l.dpid2) not in self.link_allocated_bytes:
                # Initialize link load state and capacity boundary
                self.link_allocated_bytes[(l.dpid1, l.dpid2)] = 0
                self.link_max_capacity[(l.dpid1, l.dpid2)] = self.DEFAULT_LINK_CAPACITY
        
        # We intentionally omit removing links from our internal graph when STP blocks them.
        # This SDN trick ensures the controller remembers all physical paths, enabling full ECMP.

    def _get_shortest_paths(self, src_dpid, dst_dpid):
        """
        Breadth-First Search (BFS) implementation to find ALL equal-cost shortest paths.
        Crucial for Equal-Cost Multi-Path (ECMP) routing capabilities.
        """
        if src_dpid == dst_dpid:
            return [[src_dpid]]
            
        queue = [[src_dpid]]
        shortest_paths = []
        min_length = float('inf')
        
        while queue:
            path = queue.pop(0)
            current_dpid = path[-1]
            
            # Stop branching if we exceed the optimal path length found so far
            if len(path) > min_length:
                break
                
            for next_dpid in self.adjacency.get(current_dpid, {}):
                if next_dpid not in path: 
                    new_path = list(path)
                    new_path.append(next_dpid)
                    
                    if next_dpid == dst_dpid:
                        shortest_paths.append(new_path)
                        min_length = len(new_path)
                    else:
                        queue.append(new_path)
        return shortest_paths

    def _handle_PacketIn(self, event):
        """
        Triggered when a switch doesn't know how to route a packet.
        Acts as the central brain for Traffic Characterization and Control.
        """
        packet = event.parsed
        if not packet.parsed or packet.type == packet.LLDP_TYPE:
            return

        ip_packet = packet.find('ipv4')
        if ip_packet is not None:
            src_ip_str = str(ip_packet.srcip)
            
            # --- DYNAMIC HOST DISCOVERY ---
            if src_ip_str not in self.host_locations:
                is_trunk = False
                for dpid2, port in self.adjacency.get(event.dpid, {}).items():
                    if port == event.port:
                        is_trunk = True
                        break
                if not is_trunk:
                    self.host_locations[src_ip_str] = (event.dpid, event.port)
                    
            tcp_packet = packet.find('tcp')
            if tcp_packet is not None:
                dst_ip = str(ip_packet.dstip)
                dst_port = tcp_packet.dstport
                key = (dst_ip, dst_port)

                # Check if traffic is directed towards a registered ML Collector
                if key in self.training_sessions:
                    
                    is_new_discovery = False
                    
                    # 1 & 2. WORKER DISCOVERY & TRAFFIC CHARACTERIZATION
                    if src_ip_str not in self.training_sessions[key]:
                        self.training_sessions[key].add(src_ip_str)
                        current_time = time.time()
                        self.traffic_stats[key][src_ip_str] = {
                            'phi_v': current_time,
                            'last_burst_time': current_time,
                            'T_v': 0.0,
                            'D_v': 0
                        }
                        log.info("*" * 40)
                        log.info(f"NEW WORKER DISCOVERED! IP: {src_ip_str}")
                        is_new_discovery = True
                    else:
                        current_time = time.time()
                        stats = self.traffic_stats[key][src_ip_str]
                        time_diff = current_time - stats['last_burst_time']
                        
                        # Use a 5.0s threshold to ignore iperf3 handshakes
                        if time_diff > 5.0:
                            stats['T_v'] = time_diff
                            stats['last_burst_time'] = current_time
                            stats['phi_v'] = current_time 
                            is_new_discovery = True

                    # 3. VOLUME-AWARE TRAFFIC CONTROL (RESIDUAL CAPACITY ALLOCATION)
                    # FIX: We check that not only the Destination, but also the Source is known
                    if dst_ip in self.host_locations and src_ip_str in self.host_locations:
                        dst_dpid, final_out_port = self.host_locations[dst_ip]
                        # FIX: We ALWAYS take the true origin node of the Worker
                        src_dpid, _ = self.host_locations[src_ip_str]
                        
                        # Enforce Path Pinning to strictly prevent TCP reordering
                        if src_ip_str in self.assigned_paths:
                            chosen_path = self.assigned_paths[src_ip_str]
                        else:
                            # FIX: We calculate the path from end-to-end
                            # ignoring which switch raised the event at this moment
                            paths = self._get_shortest_paths(src_dpid, dst_dpid)
                            if not paths:
                                return
                            
                            worker_expected_bytes = self.traffic_stats[key][src_ip_str]['D_v']
                            if worker_expected_bytes == 0:
                                worker_expected_bytes = 1048576 
                                
                            log.info("=" * 50)
                            log.info(f"[ROUTING DECISION] Evaluating ECMP paths for Worker {src_ip_str}")
                            log.info(f"[ROUTING DECISION] Expected Payload (D_v): {worker_expected_bytes} Bytes")
                            log.info(f"[ROUTING DECISION] Found {len(paths)} available paths to destination.")
                                
                            best_path = paths[0]
                            min_saturation_percentage = float('inf')
                            
                            for p in paths:
                                path_bottleneck_saturation = 0.0
                                
                                for i in range(len(p)-1):
                                    edge = (p[i], p[i+1])
                                    current_allocated = self.link_allocated_bytes.get(edge, 0)
                                    capacity = self.link_max_capacity.get(edge, self.DEFAULT_LINK_CAPACITY)
                                    
                                    simulated_load = current_allocated + worker_expected_bytes
                                    saturation_percentage = (simulated_load / capacity) * 100
                                    
                                    if saturation_percentage > path_bottleneck_saturation:
                                        path_bottleneck_saturation = saturation_percentage
                                
                                readable_path = [dpid_to_str(dpid) for dpid in p]
                                log.info(f"  --> Option: Path {readable_path} | Simulated Bottleneck: {path_bottleneck_saturation:.4f}%")
                                
                                if path_bottleneck_saturation < min_saturation_percentage:
                                    min_saturation_percentage = path_bottleneck_saturation
                                    best_path = p
                            
                            readable_best_path = [dpid_to_str(dpid) for dpid in best_path]
                            log.info(f"[ROUTING DECISION] WINNER: Path {readable_best_path} selected.")
                            log.info("=" * 50)
                            
                            self.assigned_paths[src_ip_str] = best_path
                            for i in range(len(best_path)-1):
                                edge = (best_path[i], best_path[i+1])
                                self.link_allocated_bytes[edge] = self.link_allocated_bytes.get(edge, 0) + worker_expected_bytes
                                
                            chosen_path = best_path

                        # FORWARDING EXECUTION
                        if event.dpid == chosen_path[-1]:
                            out_port = final_out_port
                        else:
                            try:
                                hop_index = chosen_path.index(event.dpid)
                                next_hop_dpid = chosen_path[hop_index + 1]
                                out_port = self.adjacency[event.dpid][next_hop_dpid]
                            except ValueError:
                                # The packet is on a switch outside the assigned path (Flooding Bug mitigated).
                                # The controller does not install the rule, the packet dies and the network settles immediately.
                                return

                        # Construct and deploy the hardware flow rule
                        msg = of.ofp_flow_mod()
                        msg.match = of.ofp_match(dl_type=0x0800, nw_proto=6, nw_src=ip_packet.srcip, nw_dst=ip_packet.dstip, tp_dst=dst_port)
                        # Idle timeout triggers the FlowRemoved event needed for D_v calculation
                        msg.idle_timeout = 2 
                        msg.flags = of.OFPFF_SEND_FLOW_REM 
                        msg.buffer_id = event.ofp.buffer_id 
                        msg.actions.append(of.ofp_action_output(port=out_port))
                        event.connection.send(msg)
                        return 

        # 4. BASIC FALLBACK FORWARDING
        # Handles ARP requests and generic background traffic by flooding locally
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port 
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

    def _handle_FlowRemoved(self, event):
        """
        Fired by the switch hardware when a burst concludes (idle_timeout expires).
        Crucial for precisely extracting the transmitted volume (D_v).
        """
        if event.ofp.match.dl_type == 0x0800 and event.ofp.match.nw_proto == 6:
            src_ip = str(event.ofp.match.nw_src)
            dst_ip = str(event.ofp.match.nw_dst)
            dst_port = event.ofp.match.tp_dst
            key = (dst_ip, dst_port)

            # Prevent duplicate burst logs by filtering FlowRemoved events 
            # originating from intermediate spines. Only process from the Ingress Leaf.
            worker_dpid = self.host_locations.get(src_ip, (None, None))[0]
            if event.dpid != worker_dpid:
                return

            if key in self.traffic_stats and src_ip in self.traffic_stats[key]:
                # Extract accurate byte metrics directly from the switch counters
                self.traffic_stats[key][src_ip]['D_v'] = event.ofp.byte_count
                raw_phi = self.traffic_stats[key][src_ip]['phi_v']
                
                # Format timestamps to Italian Timezone (UTC+2) for readability
                italy_tz = timezone(timedelta(hours=2))
                formatted_phi = datetime.fromtimestamp(raw_phi, tz=italy_tz).strftime('%H:%M:%S')
                
                log.info("-" * 40)
                log.info(f"BURST COMPLETED! Worker: {src_ip}")
                log.info(f"Phase (phi_v): {raw_phi:.2f} [{formatted_phi}]")
                log.info(f"Data per round (D_v): {self.traffic_stats[key][src_ip]['D_v']} bytes")
                log.info(f"Transmission Period (T_v): {self.traffic_stats[key][src_ip]['T_v']:.2f} sec")
                log.info("-" * 40)

def launch(collectors="10.0.0.101:8000,10.0.0.102:8000", link_capacity=10000000):
    """
    Module entry point called by the POX core.
    Allows injecting dynamic parameters via command line flags.
    """
    known_collectors = []
    if collectors:
        for c in collectors.split(','):
            ip, port = c.split(':')
            known_collectors.append((ip, int(port)))

    # Instantiate the controller class within the POX framework
    core.registerNew(MLController, known_collectors, link_capacity)
    log.info("ML Controller started. Ready for Volume-Aware Load Balancing.")