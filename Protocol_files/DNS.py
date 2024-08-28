from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw

def handle_dns(packet):
    dns_layer = packet[DNS]
    
    queries = [{
        "name": q.qname.decode(errors='ignore'),
        "type": q.qtype,
        "class": q.qclass
    } for q in dns_layer[DNSQR]]
    
    answers = [{
        "name": a.rrname.decode(errors='ignore'),
        "type": a.type,
        "class": a.rrclass,
        "ttl": a.ttl,
        "data": a.rdata
    } for a in dns_layer[DNSRR]]
    
    authorities = [{
        "name": a.rrname.decode(errors='ignore'),
        "type": a.type,
        "class": a.rrclass,
        "ttl": a.ttl,
        "data": a.rdata
    } for a in dns_layer[DNSRR] if a.type == 2]  # Assuming type 2 for authority
    
    additionals = [{
        "name": a.rrname.decode(errors='ignore'),
        "type": a.type,
        "class": a.rrclass,
        "ttl": a.ttl,
        "data": a.rdata
    } for a in dns_layer[DNSRR] if a.type == 1]  # Assuming type 1 for additional records
    
    dns_info = {
        "transaction_id": dns_layer.id,
        "qr": dns_layer.qr,
        "opcode": dns_layer.opcode,
        "aa": dns_layer.aa,
        "tc": dns_layer.tc,
        "rd": dns_layer.rd,
        "ra": dns_layer.ra,
        "z": dns_layer.z,
        "rcode": dns_layer.rcode,
        "question_count": dns_layer.qdcount,
        "answer_count": dns_layer.ancount,
        "authority_count": dns_layer.nscount,
        "additional_count": dns_layer.arcount,
        "queries": queries,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
        "payload": packet[Raw].load.decode(errors='ignore') if packet.haslayer(Raw) else ""
    }
    
    return dns_info
