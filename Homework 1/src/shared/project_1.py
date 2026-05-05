import time
from datetime import datetime, timezone, timedelta
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp

# Initialize the logger to print messages to the console
log = core.getLogger()

class MLController(object):
    # Allow passing the known collectors dynamically upon initialization
    def __init__(self, known_collectors):
        # Tell POX to send us OpenFlow events (like PacketIn and FlowRemoved)
        core.openflow.addListeners(self)
        
        # Initialize dynamically based on the known collectors provided
        self.training_sessions = {}
        
        # Requirement 2: Traffic Characterization Data Structure
        # We store the stats (phi_v, T_v, D_v) for each worker
        self.traffic_stats = {}
        
        for collector in known_collectors:
            self.training_sessions[collector] = set()
            self.traffic_stats[collector] = {}

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        # Ignore LLDP packets (used by POX discovery module) to prevent broadcast storms
        if packet.type == packet.LLDP_TYPE:
            return

        ip_packet = packet.find('ipv4')
        if ip_packet is not None:
            tcp_packet = packet.find('tcp')
            if tcp_packet is not None:
                src_ip = str(ip_packet.srcip)
                dst_ip = str(ip_packet.dstip)
                dst_port = tcp_packet.dstport
                key = (dst_ip, dst_port)

                # Check if the destination is one of our known collectors
                if key in self.training_sessions:
                    
                    # 1. WORKER DISCOVERY LOGIC
                    if src_ip not in self.training_sessions[key]:
                        self.training_sessions[key].add(src_ip)
                        
                        current_time = time.time()
                        # Initialize stats for the new worker
                        self.traffic_stats[key][src_ip] = {
                            'phi_v': current_time, # Phase: Absolute start time of the first burst
                            'last_burst_time': current_time,
                            'T_v': 0.0,            # Period
                            'D_v': 0               # Data per round (Bytes)
                        }
                        
                        log.info("*" * 40)
                        log.info(f"NEW WORKER DISCOVERED! IP: {src_ip} -> collector {key}")
                        # Kv is simply the length of the set
                        log.info(f"Current K_v (Number of workers): {len(self.training_sessions[key])}")
                        log.info("*" * 40)
                    else:
                        # 2. TRAFFIC CHARACTERIZATION LOGIC (Timing)
                        # If a known worker triggers a PacketIn, a new burst has started 
                        # because the previous flow rule expired.
                        current_time = time.time()
                        stats = self.traffic_stats[key][src_ip]
                        time_diff = current_time - stats['last_burst_time']

                        # Update period (T_v) only if a significant time has passed to avoid micro-interrupts
                        if time_diff > 1.0:
                            stats['T_v'] = time_diff
                            stats['last_burst_time'] = current_time
                            stats['phi_v'] = current_time # Update phase to the start of the new burst

                    # Install a flow rule to handle the remainder of this burst efficiently
                    msg = of.ofp_flow_mod()
                    # We must explicitly match IP and TCP (dl_type=0x0800, nw_proto=6)
                    msg.match = of.ofp_match(dl_type=0x0800, nw_proto=6, nw_src=ip_packet.srcip, nw_dst=ip_packet.dstip, tp_dst=dst_port)
                    
                    # Expire the rule after 2 seconds of silence (end of burst)
                    msg.idle_timeout = 2 
                    # Flag to ask the switch to notify us when the rule expires (to get D_v)
                    msg.flags = of.OFPFF_SEND_FLOW_REM 
                    
                    # Tell the switch to also forward the specific packet that triggered this event
                    msg.buffer_id = event.ofp.buffer_id 
                    
                    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                    event.connection.send(msg)
                    
                    # Return immediately so we do not trigger the default flood below
                    return

        # 4. BASIC FORWARDING (Flood) — MUST be outside all ifs!
        # This handles ARP and non-training traffic
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        
        # Explicitly state the input port so the switch handles FLOOD correctly without dropping ARP
        msg.in_port = event.port 
        
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

    def _handle_FlowRemoved(self, event):
        """
        This function is triggered automatically when a flow rule expires due to idle_timeout.
        It allows us to read the total byte_count (D_v) of the completed burst directly from the switch.
        """
        # Ensure we are analyzing an IPv4/TCP flow removal
        if event.ofp.match.dl_type == 0x0800 and event.ofp.match.nw_proto == 6:
            src_ip = str(event.ofp.match.nw_src)
            dst_ip = str(event.ofp.match.nw_dst)
            dst_port = event.ofp.match.tp_dst
            key = (dst_ip, dst_port)

            # 2. TRAFFIC CHARACTERIZATION LOGIC (Data Volume)
            if key in self.traffic_stats and src_ip in self.traffic_stats[key]:
                # event.ofp.byte_count contains the total data sent in this specific burst
                self.traffic_stats[key][src_ip]['D_v'] = event.ofp.byte_count
                
                raw_phi = self.traffic_stats[key][src_ip]['phi_v']
                
                # Define Italian Timezone (UTC+2 for CEST)
                italy_tz = timezone(timedelta(hours=2))
                # Convert the Unix timestamp to Italian time format (HH:MM:SS)
                formatted_phi = datetime.fromtimestamp(raw_phi, tz=italy_tz).strftime('%H:%M:%S')
                
                log.info("-" * 40)
                log.info(f"BURST COMPLETED! Worker: {src_ip}")
                log.info(f"Phase (phi_v): {raw_phi:.2f} [{formatted_phi}]")
                log.info(f"Data per round (D_v): {self.traffic_stats[key][src_ip]['D_v']} bytes")
                log.info(f"Transmission Period (T_v): {self.traffic_stats[key][src_ip]['T_v']:.2f} sec")
                log.info("-" * 40)

# Add parameters to the launch function to accept command-line arguments
def launch(collectors="10.0.0.101:8000,10.0.0.102:8000"):
    """
    This is the entry point that POX calls when the module starts.
    You can pass the collectors dynamically from the command line.
    If no arguments are passed, it defaults to the strings provided above.
    """
    # Parse the command-line string into a list of tuples (IP, Port)
    known_collectors = []
    if collectors:
        for c in collectors.split(','):
            ip, port = c.split(':')
            known_collectors.append((ip, int(port)))

    # Register our controller class with POX, passing the dynamic configuration
    core.registerNew(MLController, known_collectors)
    log.info("ML Controller started. Waiting for training traffic...")
    log.info(f"Configured collectors: {known_collectors}")