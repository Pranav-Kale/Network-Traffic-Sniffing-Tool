import json
import socket
from collections import defaultdict

# Define the file paths
PACKET_DATA_FILE = 'packets.json'
ANALYSIS_DATA_FILE = 'analysis.json'

def reverse_dns_lookup(ip_addresses):
    domains = {}
    for ip in ip_addresses:
        try:
            # Perform reverse DNS lookup
            domain = socket.gethostbyaddr(ip)[0]
            domains[ip] = domain
        except socket.herror:
            # Handle case where reverse DNS lookup fails
            domains[ip] = 'No domain found'
    return domains

def load_packet_data():
    try:
        with open(PACKET_DATA_FILE, 'r') as f:
            packets = [json.loads(line) for line in f]
        print(f"Loaded {len(packets)} packets")
        return packets
    except IOError as e:
        print(f"Error reading packet data: {e}")
        return []

def analyze_packet_data(packets):
    protocol_count = defaultdict(int)
    src_ip_count = defaultdict(int)
    dst_ip_count = defaultdict(int)
    unique_ips = set()

    src_ips = set()
    dst_ips = set()

    for packet in packets:
        packet_type = packet.get('type')
        src_ip = packet.get('source_ip')
        dst_ip = packet.get('destination_ip')

        # Count protocols
        if packet_type:
            protocol_count[packet_type] += 1

        # Count IP addresses
        if src_ip:
            src_ip_count[src_ip] += 1
            unique_ips.add(src_ip)
            src_ips.add(src_ip)
        if dst_ip:
            dst_ip_count[dst_ip] += 1
            unique_ips.add(dst_ip)
            dst_ips.add(dst_ip)

    ip_domains = reverse_dns_lookup(src_ips.union(dst_ips))


    src_ip_count_formatted = {ip: f" - {count} times repeated" for ip, count in src_ip_count.items()}
    dst_ip_count_formatted = {ip: f" - {count} times repeated" for ip, count in dst_ip_count.items()}
    unique_ips_formatted = {ip: f" - {ip_domains.get(ip)}" for ip in unique_ips}


    return protocol_count, src_ip_count_formatted, dst_ip_count_formatted, unique_ips_formatted

def analyze_tcp_flags(packets):
    flag_count = {
        "SYN": 0,
        "ACK": 0,
        "FIN": 0,
        "RST": 0,
        "PSH": 0,
        "URG": 0
    }
    for packet in packets:
        if packet.get('type') == 'TCP':
            flags = packet.get('flags', '')
            if 'S' in flags:
                flag_count["SYN"] += 1
            if 'A' in flags:
                flag_count["ACK"] += 1
            if 'F' in flags:
                flag_count["FIN"] += 1
            if 'R' in flags:
                flag_count["RST"] += 1
            if 'P' in flags:
                flag_count["PSH"] += 1
            if 'U' in flags:
                flag_count["URG"] += 1

    return flag_count

def save_analysis_to_file(protocol_count, src_ip_count, dst_ip_count, unique_ips, flag_count):
    analysis = {
        "protocol_count": dict(protocol_count),
        "src_ip_count": src_ip_count,
        "dst_ip_count": dst_ip_count,
        "unique_ips": unique_ips,
        "tcp_flags": flag_count
    }

    try:
        with open(ANALYSIS_DATA_FILE, 'w') as f:
            json.dump(analysis, f, indent=4)
        print(f"Analysis saved to {ANALYSIS_DATA_FILE}")
    except IOError as e:
        print(f"Error writing analysis data: {e}")

def main():
    packets = load_packet_data()
    if packets:
        protocol_count, src_ip_count, dst_ip_count, unique_ips = analyze_packet_data(packets)
        flag_count = analyze_tcp_flags(packets)  # Analyze TCP flags

        # Save analysis results to file
        save_analysis_to_file(protocol_count, src_ip_count, dst_ip_count, unique_ips, flag_count)

if __name__ == "__main__":
    main()
