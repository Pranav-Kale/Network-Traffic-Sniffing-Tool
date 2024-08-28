from scapy.layers.inet import TCP
from scapy.packet import Raw

def handle_tcp(packet):
    tcp_layer = packet[TCP]
    details = {
        "source_port": tcp_layer.sport,
        "destination_port": tcp_layer.dport,
        "flags": tcp_layer.flags,
        "seq_number": tcp_layer.seq,
        "ack_number": tcp_layer.ack,
        "data_offset": tcp_layer.dataofs,
        "reserved": tcp_layer.reserved,
        "window_size": tcp_layer.window,
        "checksum": tcp_layer.chksum,
        "urgent_pointer": tcp_layer.urgptr,
        "options": tcp_layer.options,
        "payload": packet[Raw].load.decode(errors='ignore') if packet.haslayer(Raw) else ""
    }
    return details
