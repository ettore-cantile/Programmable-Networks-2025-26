from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp

# Initialize the logger to print messages to the console
log = core.getLogger()

class MLController(object):
    # Allow passing the known collectors dynamically upon initialization
    def __init__(self, known_collectors):
        # Tell POX to send us OpenFlow events (like PacketIn)
        core.openflow.addListeners(self)
        
        # Requirement 1: Worker Discovery Data Structure
        # Initialize dynamically based on the known collectors provided
        self.training_sessions = {}
        for collector in known_collectors:
            self.training_sessions[collector] = set()

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        # Ignore LLDP packets (used by POX discovery module) to prevent broadcast storms
        if packet.type == packet.LLDP_TYPE:
            return

        # 1. WORKER DISCOVERY LOGIC (only for TCP towards collectors)
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
                    # Add the worker if it is not already tracked
                    if src_ip not in self.training_sessions[key]:
                        self.training_sessions[key].add(src_ip)
                        log.info("*" * 40)
                        log.info(f"NEW WORKER DISCOVERED! IP: {src_ip} -> collector {key}")
                        log.info(f"Training {dst_ip}:{dst_port} workers: {self.training_sessions[key]}")
                        log.info("*" * 40)

        # 2. BASIC FORWARDING (Flood) — MUST be outside all ifs!
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

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