from scapy.layers.inet import ICMP
from scapy.packet import Raw

def handle_icmp(packet):
    icmp_layer = packet[ICMP]
    icmp_info = {
        "type": icmp_layer.type,
        "code": icmp_layer.code,
        "id": icmp_layer.id if hasattr(icmp_layer, 'id') else None,
        "seq": icmp_layer.seq if hasattr(icmp_layer, 'seq') else None,
        "payload": packet[Raw].load.decode(errors='ignore') if packet.haslayer(Raw) else ""
    }
    return icmp_info
