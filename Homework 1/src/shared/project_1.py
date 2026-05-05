from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp

# Initialize the logger to print messages to the console
log = core.getLogger()

class MLController(object):
    def __init__(self):
        # Tell POX to send us OpenFlow events (like PacketIn)
        core.openflow.addListeners(self)
        
        # Requirement 1: Worker Discovery Data Structure
        # We store a set of worker IPs for each known collector
        self.training_sessions = {
            ("10.0.0.101", 8000): set(),
            ("10.0.0.102", 8000): set()
        }

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        # 1. WORKER DISCOVERY LOGIC (solo per TCP verso i collector)
        ip_packet = packet.find('ipv4')
        if ip_packet is not None:
            tcp_packet = packet.find('tcp')
            if tcp_packet is not None:
                src_ip = str(ip_packet.srcip)
                dst_ip = str(ip_packet.dstip)
                
                dst_port = tcp_packet.dstport
                key = (dst_ip, dst_port)

                if key in self.training_sessions:
                    if src_ip not in self.training_sessions[key]:
                        self.training_sessions[key].add(src_ip)
                        log.info("*" * 40)
                        log.info(f"NEW WORKER DISCOVERED! IP: {src_ip} -> collector {key}")
                        log.info(f"Training {dst_ip}:{dst_port} workers: {self.training_sessions[key]}")
                        log.info("*" * 40)

        # 2. BASIC FORWARDING (Flood) — DEVE essere fuori da tutti gli if!
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

def launch():
    """
    This is the entry point that POX calls when the module starts.
    """
    # Register our controller class with POX
    core.registerNew(MLController)
    log.info("ML Controller started. Waiting for training traffic...")