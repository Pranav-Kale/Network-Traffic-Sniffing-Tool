from scapy.all import sniff
import json
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from Protocol_files.TCP import handle_tcp
from Protocol_files.UDP import handle_udp
from Protocol_files.ICMP import handle_icmp
from Protocol_files.DNS import handle_dns
from Protocol_files.DHCP import handle_dhcp


PACKET_DATA_FILE = 'packets.json'


def save_packet_data(packet_info):
    try:
        with open(PACKET_DATA_FILE, 'a') as f:
            f.write(json.dumps(packet_info) + "\n")
    except TypeError as e:
        print(f"TypeError: {e} ")
    except IOError as e:
        print(f"Error saving packet data: {e}")


def packet_handler(packet):
    packet_info = {"timestamp": datetime.now().isoformat()}

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        packet_info.update({
            "source_ip": ip_layer.src,
            "destination_ip": ip_layer.dst
        })

        if packet.haslayer(TCP):
            packet_info["type"] = "TCP"
            packet_info.update(handle_tcp(packet))
            # Convert flags to a string because FLAGVALUE is causing trouble
            if "flags" in packet_info:
                packet_info["flags"] = str(packet_info["flags"])
        elif packet.haslayer(UDP):
            packet_info["type"] = "UDP"
            packet_info.update(handle_udp(packet))
        elif packet.haslayer(ICMP):
            packet_info["type"] = "ICMP"
            packet_info.update(handle_icmp(packet))
        elif packet.haslayer(DNS):
            packet_info["type"] = "DNS"
            packet_info.update(handle_dns(packet))
        elif packet.haslayer(DHCP):
            packet_info["type"] = "DHCP"
            packet_info.update(handle_dhcp(packet))

    save_packet_data(packet_info)

try:
    sniff(prn=packet_handler)
except KeyboardInterrupt:
    print("Sniffing Stopped")



















