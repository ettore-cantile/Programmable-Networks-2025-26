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
        Dynamically builds the network graph using LLDP packets.
        Guarantees topology independence.
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
        elif event.removed:
            # Remove edge if link goes down
            if l.dpid2 in self.adjacency[l.dpid1]:
                del self.adjacency[l.dpid1][l.dpid2]

    def _get_shortest_paths(self, src_dpid, dst_dpid):
        """
        BFS implementation to find ALL equal-cost shortest paths.
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
            
            # Learn host locations (Worker or Collector) dynamically
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

                if key in self.training_sessions:
                    # 1 & 2. WORKER DISCOVERY & TRAFFIC CHARACTERIZATION
                    is_new_discovery = False
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
                        if time_diff > 1.0:
                            stats['T_v'] = time_diff
                            stats['last_burst_time'] = current_time
                            stats['phi_v'] = current_time 
                            is_new_discovery = True

                    # 3. VOLUME-AWARE TRAFFIC CONTROL (RESIDUAL CAPACITY ALLOCATION)
                    if dst_ip in self.host_locations:
                        dst_dpid, final_out_port = self.host_locations[dst_ip]
                        
                        if src_ip_str in self.assigned_paths:
                            chosen_path = self.assigned_paths[src_ip_str]
                        else:
                            paths = self._get_shortest_paths(event.dpid, dst_dpid)
                            if not paths:
                                return
                            
                            worker_expected_bytes = self.traffic_stats[key][src_ip_str]['D_v']
                            if worker_expected_bytes == 0:
                                worker_expected_bytes = 1048576 
                                
                            # RESTORED DETAILED LOGS
                            log.info(f"--- CAPACITY EVALUATION FOR WORKER {src_ip_str} ---")
                            log.info(f"Expected Worker Payload (D_v): {worker_expected_bytes} Bytes")
                                
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
                                log.info(f"  -> Path {readable_path}: Bottleneck Saturation would be {path_bottleneck_saturation:.4f}%")
                                
                                if path_bottleneck_saturation < min_saturation_percentage:
                                    min_saturation_percentage = path_bottleneck_saturation
                                    best_path = p
                            
                            readable_best_path = [dpid_to_str(dpid) for dpid in best_path]
                            log.info(f"DECISION: Assigned Path {readable_best_path} (Most Residual Capacity).")
                            log.info("-" * 45)
                            
                            self.assigned_paths[src_ip_str] = best_path
                            for i in range(len(best_path)-1):
                                edge = (best_path[i], best_path[i+1])
                                self.link_allocated_bytes[edge] = self.link_allocated_bytes.get(edge, 0) + worker_expected_bytes
                            chosen_path = best_path

                        # FORWARDING
                        if len(chosen_path) == 1 or event.dpid == chosen_path[-1]:
                            out_port = final_out_port
                        else:
                            try:
                                hop_index = chosen_path.index(event.dpid)
                                next_hop_dpid = chosen_path[hop_index + 1]
                                out_port = self.adjacency[event.dpid][next_hop_dpid]
                            except ValueError:
                                return

                        msg = of.ofp_flow_mod()
                        msg.match = of.ofp_match(dl_type=0x0800, nw_proto=6, nw_src=ip_packet.srcip, nw_dst=ip_packet.dstip, tp_dst=dst_port)
                        msg.idle_timeout = 2 
                        msg.flags = of.OFPFF_SEND_FLOW_REM 
                        msg.buffer_id = event.ofp.buffer_id 
                        msg.actions.append(of.ofp_action_output(port=out_port))
                        event.connection.send(msg)
                        return 

        # 4. BASIC FORWARDING (ARP)
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port 
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

    def _handle_FlowRemoved(self, event):
        """Extracts D_v from the expired flow."""
        if event.ofp.match.dl_type == 0x0800 and event.ofp.match.nw_proto == 6:
            src_ip = str(event.ofp.match.nw_src)
            dst_ip = str(event.ofp.match.nw_dst)
            dst_port = event.ofp.match.tp_dst
            key = (dst_ip, dst_port)

            worker_dpid = self.host_locations.get(src_ip, (None, None))[0]
            if event.dpid != worker_dpid:
                return

            if key in self.traffic_stats and src_ip in self.traffic_stats[key]:
                self.traffic_stats[key][src_ip]['D_v'] = event.ofp.byte_count
                raw_phi = self.traffic_stats[key][src_ip]['phi_v']
                
                italy_tz = timezone(timedelta(hours=2))
                formatted_phi = datetime.fromtimestamp(raw_phi, tz=italy_tz).strftime('%H:%M:%S')
                
                log.info("-" * 40)
                log.info(f"BURST COMPLETED! Worker: {src_ip}")
                log.info(f"Phase (phi_v): {raw_phi:.2f} [{formatted_phi}]")
                log.info(f"Data per round (D_v): {self.traffic_stats[key][src_ip]['D_v']} bytes")
                log.info(f"Transmission Period (T_v): {self.traffic_stats[key][src_ip]['T_v']:.2f} sec")
                log.info("-" * 40)

def launch(collectors="10.0.0.101:8000,10.0.0.102:8000", link_capacity=10000000):
    known_collectors = []
    if collectors:
        for c in collectors.split(','):
            ip, port = c.split(':')
            known_collectors.append((ip, int(port)))

    core.registerNew(MLController, known_collectors, link_capacity)
    log.info("ML Controller started. Ready for Volume-Aware Load Balancing.")