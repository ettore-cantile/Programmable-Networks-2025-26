import time
import logging
from datetime import datetime, timezone, timedelta
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.util import dpid_to_str

# Initialize the central logger
log = core.getLogger()

# Maschera gli errori fastidiosi di unpacking dei pacchetti frammentati
logging.getLogger("packet").setLevel(logging.WARNING)

class MLController(object):
    def __init__(self, known_collectors, link_capacity):
        core.openflow.addListeners(self)
        
        def _handle_core_ComponentRegistered(event):
            if event.name == "openflow_discovery":
                event.component.addListeners(self)
        core.addListenerByName("ComponentRegistered", _handle_core_ComponentRegistered)
        
        self.training_sessions = {}
        self.traffic_stats = {}
        self.adjacency = {}       
        self.host_locations = {}  
        
        self.link_allocated_rate = {} 
        self.DEFAULT_LINK_CAPACITY = int(link_capacity)
        self.link_max_capacity = {}
        self.assigned_paths = {}    
        
        for collector in known_collectors:
            self.training_sessions[collector] = set()
            self.traffic_stats[collector] = {}

    def _handle_LinkEvent(self, event):
        l = event.link
        if l.dpid1 not in self.adjacency:
            self.adjacency[l.dpid1] = {}
            
        if event.added:
            self.adjacency[l.dpid1][l.dpid2] = l.port1
            if (l.dpid1, l.dpid2) not in self.link_allocated_rate:
                self.link_allocated_rate[(l.dpid1, l.dpid2)] = 0
                self.link_max_capacity[(l.dpid1, l.dpid2)] = self.DEFAULT_LINK_CAPACITY

    def _get_shortest_paths(self, src_dpid, dst_dpid):
        """Fixed BFS: Returns ONLY the absolute shortest paths (Strict ECMP)"""
        if src_dpid == dst_dpid: return [[src_dpid]]
        
        paths = []
        queue = [(src_dpid, [src_dpid])]
        min_length = float('inf')
        
        while queue:
            (current, path) = queue.pop(0)
            if len(path) > min_length: continue
            
            for neighbor in self.adjacency.get(current, {}):
                if neighbor == dst_dpid:
                    new_path = path + [neighbor]
                    if len(new_path) < min_length:
                        min_length = len(new_path)
                        paths = [new_path]
                    elif len(new_path) == min_length:
                        paths.append(new_path)
                elif neighbor not in path:
                    queue.append((neighbor, path + [neighbor]))
        return paths

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed or packet.type == packet.LLDP_TYPE: return

        ip_packet = packet.find('ipv4')
        if ip_packet is not None:
            src_ip_str = str(ip_packet.srcip)
            
            if src_ip_str not in self.host_locations:
                is_trunk = False
                for dpid2, port in self.adjacency.get(event.dpid, {}).items():
                    if port == event.port: is_trunk = True; break
                if not is_trunk: self.host_locations[src_ip_str] = (event.dpid, event.port)
                    
            tcp_packet = packet.find('tcp')
            if tcp_packet is not None:
                dst_ip = str(ip_packet.dstip)
                dst_port = tcp_packet.dstport
                key = (dst_ip, dst_port)

                if key in self.training_sessions:
                    if src_ip_str not in self.training_sessions[key]:
                        self.training_sessions[key].add(src_ip_str)
                        current_time = time.time()
                        self.traffic_stats[key][src_ip_str] = {
                            'phi_v': current_time, 
                            'last_burst_time': current_time,
                            'T_v': 0.0,
                            'D_v': 1048576, 
                            'current_round_accumulator': 0
                        }
                        log.info("*" * 40)
                        log.info(f"NEW WORKER DISCOVERED! IP: {src_ip_str}")
                    else:
                        current_time = time.time()
                        stats = self.traffic_stats[key][src_ip_str]
                        time_diff = current_time - stats['last_burst_time']
                        
                        # =======================================================
                        # 1. SOGLIA RILEVAMENTO DINAMICA (Indipendente dalla scala)
                        # =======================================================
                        if stats['T_v'] > 0:
                            # Filtra rigorosamente i fantasmi TCP aspettando il 75% del periodo
                            round_threshold = stats['T_v'] * 0.75 
                        else:
                            round_threshold = 5.0 # Valore di fallback al primo round
                            
                        if time_diff > round_threshold: 
                            if stats['current_round_accumulator'] > 100000: 
                                stats['D_v'] = stats['current_round_accumulator']
                            
                            stats['current_round_accumulator'] = 0
                            
                            if stats['T_v'] == 0: 
                                stats['T_v'] = time_diff 
                            elif time_diff < (stats['T_v'] * 2.0): 
                                stats['T_v'] = (0.5 * stats['T_v']) + (0.5 * time_diff)
                                
                            stats['last_burst_time'] = current_time

                    if dst_ip in self.host_locations and src_ip_str in self.host_locations:
                        dst_dpid, final_out_port = self.host_locations[dst_ip]
                        src_dpid, _ = self.host_locations[src_ip_str]
                        
                        if src_ip_str in self.assigned_paths:
                            chosen_path = self.assigned_paths[src_ip_str]
                        else:
                            paths = self._get_shortest_paths(src_dpid, dst_dpid)
                            if not paths: return
                            
                            stats = self.traffic_stats[key][src_ip_str]
                            worker_rate = float(stats['D_v']) / (stats['T_v'] if stats['T_v'] > 0 else 1.0)
                            
                            log.info("=" * 50)
                            log.info(f"[ROUTING DECISION] Evaluating ECMP paths for Worker {src_ip_str}")
                            log.info(f"[ROUTING DECISION] Expected Payload: {stats['D_v']} Bytes | Period: {stats['T_v']:.2f} s")
                            log.info(f"[ROUTING DECISION] Predicted Link Load: {worker_rate:.2f} Bytes/sec")
                                
                            best_path = paths[0]
                            min_saturation = float('inf')
                            for p in paths:
                                path_bottleneck = 0.0
                                for i in range(len(p)-1):
                                    edge = (p[i], p[i+1])
                                    load = self.link_allocated_rate.get(edge, 0)
                                    cap = self.link_max_capacity.get(edge, self.DEFAULT_LINK_CAPACITY)
                                    sat = ((load + worker_rate) / cap) * 100
                                    if sat > path_bottleneck: path_bottleneck = sat
                                
                                readable_path = [dpid_to_str(dpid) for dpid in p]
                                log.info(f"  --> Option: Path {readable_path} | Simulated Bottleneck: {path_bottleneck:.4f}%")
                                
                                if path_bottleneck < min_saturation:
                                    min_saturation = path_bottleneck
                                    best_path = p
                            
                            readable_best_path = [dpid_to_str(dpid) for dpid in best_path]
                            log.info(f"[ROUTING DECISION] WINNER: Path {readable_best_path} selected.")
                            log.info("=" * 50)
                            
                            self.assigned_paths[src_ip_str] = best_path
                            for i in range(len(best_path)-1):
                                e = (best_path[i], best_path[i+1])
                                self.link_allocated_rate[e] = self.link_allocated_rate.get(e, 0) + worker_rate
                            chosen_path = best_path

                        if event.dpid == chosen_path[-1]: 
                            out_port = final_out_port
                        else:
                            try:
                                idx = chosen_path.index(event.dpid)
                                out_port = self.adjacency[event.dpid][chosen_path[idx + 1]]
                            except: return

                        # Match esatto anche sulla porta TCP sorgente per isolare i round
                        msg = of.ofp_flow_mod()
                        msg.match = of.ofp_match(
                            dl_type=0x0800, 
                            nw_proto=6, 
                            nw_src=ip_packet.srcip, 
                            nw_dst=ip_packet.dstip, 
                            tp_src=tcp_packet.srcport,
                            tp_dst=dst_port
                        )
                        
                        # =======================================================
                        # 2. CALCOLO TIMEOUT DINAMICI (Dipendenti da T_v)
                        # =======================================================
                        current_Tv = self.traffic_stats[key][src_ip_str]['T_v']
                        
                        if current_Tv > 0:
                            # Idle: 20% del periodo (es. 20s -> 4s). Minimo garantito di 3s per robustezza TCP.
                            dynamic_idle = max(3, int(current_Tv * 0.2))
                            # Hard: Taglia la regola appena prima del round successivo (es. 20s -> 19s).
                            dynamic_hard = max(dynamic_idle + 1, int(current_Tv - 1))
                        else:
                            # Primo round assoluto: ci affidiamo a un idle_timeout di fallback (0 significa infinito per hard)
                            dynamic_idle = 5
                            dynamic_hard = 0 
                        
                        msg.idle_timeout = dynamic_idle
                        if dynamic_hard > 0:
                            msg.hard_timeout = dynamic_hard
                            
                        msg.flags |= of.OFPFF_SEND_FLOW_REM 
                        msg.buffer_id = event.ofp.buffer_id
                        msg.actions.append(of.ofp_action_output(port=out_port))
                        event.connection.send(msg)
                        return 

        msg = of.ofp_packet_out(data=event.ofp, in_port=event.port)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

    def _handle_FlowRemoved(self, event):
        match = event.ofp.match
        if match.dl_type == 0x0800 and match.nw_proto == 6:
            if not match.nw_src or not match.nw_dst: return
            
            src_ip = str(match.nw_src)
            dst_ip = str(match.nw_dst)
            dst_port = match.tp_dst if match.tp_dst is not None else 8000
            key = (dst_ip, dst_port)
            
            worker_dpid = self.host_locations.get(src_ip, (None, None))[0]
            if event.dpid != worker_dpid: return

            if key in self.traffic_stats and src_ip in self.traffic_stats[key]:
                stats = self.traffic_stats[key][src_ip]
                stats['current_round_accumulator'] += event.ofp.byte_count
                
                path = self.assigned_paths.get(src_ip)
                if path:
                    rate = float(stats['D_v']) / (stats['T_v'] if stats['T_v'] > 0 else 1.0)
                    for i in range(len(path)-1):
                        e = (path[i], path[i+1])
                        self.link_allocated_rate[e] = max(0, self.link_allocated_rate.get(e, 0) - rate)
                    
                    # Libera il percorso in modo che il prossimo round ricalcoli l'ECMP
                    del self.assigned_paths[src_ip]

                # Log del singolo worker per il debug
                log.info("-" * 40)
                log.info(f"BURST COMPLETED! Worker: {src_ip} ha terminato l'invio.")
                log.info("-" * 40)

                # =================================================================
                # CALCOLO AGGREGATO DELLE METRICHE DELLA "TRAINING PROCEDURE v"
                # =================================================================
                session_stats = self.traffic_stats[key]
                
                K_v = len(session_stats)
                
                phi_v_raw = min(s['phi_v'] for s in session_stats.values())
                italy_tz = timezone(timedelta(hours=2))
                phi_v_formatted = datetime.fromtimestamp(phi_v_raw, tz=italy_tz).strftime('%H:%M:%S')
                
                D_v = sum(s['D_v'] for s in session_stats.values())
                
                valid_periods = [s['T_v'] for s in session_stats.values() if s['T_v'] > 0]
                T_v = sum(valid_periods) / len(valid_periods) if valid_periods else 0.0
                
                log.info("#" * 55)
                log.info(f"--- TRAINING PROCEDURE [v] STATS UPDATED ---")
                log.info(f"Collector Target : {dst_ip}:{dst_port}")
                log.info(f"Active Workers   (K_v) : {K_v}")
                log.info(f"Start Phase      (phi_v): {phi_v_raw:.2f} [{phi_v_formatted}]")
                log.info(f"Total Data/Round (D_v) : {D_v} bytes (Sum)")
                log.info(f"Training Period  (T_v) : {T_v:.2f} sec (Avg)")
                log.info("#" * 55)

def launch(collectors="10.0.0.101:8000,10.0.0.102:8000", link_capacity=10000000):
    known_collectors = []
    for c in collectors.split(','):
        ip, port = c.split(':')
        known_collectors.append((ip, int(port)))
    core.registerNew(MLController, known_collectors, link_capacity)
    log.info("Volume & Time Aware ML Controller started. Ready for Load Balancing.")