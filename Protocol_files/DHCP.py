from scapy.layers.dhcp import DHCP
from scapy.packet import Raw

def handle_dhcp(packet):
    dhcp_layer = packet[DHCP]
    options = {opt[0]: opt[1] for opt in dhcp_layer.options}  # Convert options to a dictionary
    return {
        "operation_code": dhcp_layer.op,
        "hardware_type": dhcp_layer.htype,
        "hardware_length": dhcp_layer.hlen,
        "hops": dhcp_layer.hops,
        "transaction_id": dhcp_layer.xid,
        "seconds": dhcp_layer.secs,
        "flags": dhcp_layer.flags,
        "client_ip_address": dhcp_layer.ciaddr,
        "your_ip_address": dhcp_layer.yiaddr,
        "server_ip_address": dhcp_layer.siaddr,
        "gateway_ip_address": dhcp_layer.giaddr,
        "client_hardware_address": dhcp_layer.chaddr,
        "server_name": dhcp_layer.sname,
        "boot_file_name": dhcp_layer.file,
        "options": options,
        "payload": packet[Raw].load.decode(errors='ignore') if packet.haslayer(Raw) else ""
    }
