from scapy.layers.inet import UDP
from scapy.packet import Raw

def handle_udp(packet):
    udp_layer = packet[UDP]
    udp_info = {
        "source_port": udp_layer.sport,
        "destination_port": udp_layer.dport,
        "length": udp_layer.len,
        "checksum": udp_layer.chksum,
        "payload": packet[Raw].load.decode(errors='ignore') if packet.haslayer(Raw) else ""
    }
    return udp_info
