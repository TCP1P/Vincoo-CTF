#!/usr/bin/env python3
"""
PCAP Generator Script

This script generates a network capture file containing simulated HTTP traffic.
The capture includes various network activities to make it realistic.
"""

from scapy.all import *
import random
import base64

# Configuration
OUTPUT_FILE = "../dist/capture.pcap"
SECRET_TOKEN = "SnapanCTF{s3l4m4t7t7t7t_4nd4_b4ru_s4j4_m3ng4n4l1s1s_n37w0rk_c4p7ur3}"
# Base64 encode the flag to prevent simple strings extraction
ENCODED_TOKEN = base64.b64encode(SECRET_TOKEN.encode()).decode()

# Network configuration
CLIENT_IP = "192.168.1.100"
CLIENT_MAC = "aa:bb:cc:dd:ee:01"
SERVER_IP = "10.0.0.50"
SERVER_MAC = "aa:bb:cc:dd:ee:02"
DNS_SERVER_IP = "8.8.8.8"
DNS_SERVER_MAC = "aa:bb:cc:dd:ee:03"

def create_tcp_handshake(src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, seq_start):
    """Create TCP 3-way handshake packets."""
    packets = []
    
    # SYN
    syn = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=src_port, dport=dst_port, flags="S", seq=seq_start)
    packets.append(syn)
    
    # SYN-ACK
    syn_ack = Ether(src=dst_mac, dst=src_mac) / \
              IP(src=dst_ip, dst=src_ip) / \
              TCP(sport=dst_port, dport=src_port, flags="SA", seq=1000, ack=seq_start + 1)
    packets.append(syn_ack)
    
    # ACK
    ack = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=src_port, dport=dst_port, flags="A", seq=seq_start + 1, ack=1001)
    packets.append(ack)
    
    return packets, seq_start + 1, 1001

def create_http_request(src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, seq, ack, method, path, body=None):
    """Create an HTTP request packet."""
    if body:
        http_data = f"{method} {path} HTTP/1.1\r\n"
        http_data += f"Host: internal-server.local\r\n"
        http_data += f"Content-Type: application/x-www-form-urlencoded\r\n"
        http_data += f"Content-Length: {len(body)}\r\n"
        http_data += f"Connection: keep-alive\r\n"
        http_data += f"\r\n{body}"
    else:
        http_data = f"{method} {path} HTTP/1.1\r\n"
        http_data += f"Host: internal-server.local\r\n"
        http_data += f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        http_data += f"Accept: text/html,application/json\r\n"
        http_data += f"Connection: keep-alive\r\n"
        http_data += f"\r\n"
    
    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=src_port, dport=dst_port, flags="PA", seq=seq, ack=ack) / \
          Raw(load=http_data)
    
    return pkt, seq + len(http_data)

def create_http_response(src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, seq, ack, status_code, body):
    """Create an HTTP response packet."""
    http_data = f"HTTP/1.1 {status_code}\r\n"
    http_data += f"Content-Type: application/json\r\n"
    http_data += f"Content-Length: {len(body)}\r\n"
    http_data += f"Connection: keep-alive\r\n"
    http_data += f"\r\n{body}"
    
    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=src_port, dport=dst_port, flags="PA", seq=seq, ack=ack) / \
          Raw(load=http_data)
    
    return pkt, seq + len(http_data)

def create_dns_query(client_ip, dns_ip, client_mac, dns_mac, domain):
    """Create a DNS query packet."""
    pkt = Ether(src=client_mac, dst=dns_mac) / \
          IP(src=client_ip, dst=dns_ip) / \
          UDP(sport=random.randint(49152, 65535), dport=53) / \
          DNS(rd=1, qd=DNSQR(qname=domain))
    return pkt

def create_dns_response(client_ip, dns_ip, client_mac, dns_mac, domain, resolved_ip, sport):
    """Create a DNS response packet."""
    pkt = Ether(src=dns_mac, dst=client_mac) / \
          IP(src=dns_ip, dst=client_ip) / \
          UDP(sport=53, dport=sport) / \
          DNS(rd=1, ra=1, qd=DNSQR(qname=domain), 
              an=DNSRR(rrname=domain, rdata=resolved_ip))
    return pkt

def generate_pcap():
    """Generate the complete PCAP file."""
    packets = []
    
    # Add some DNS queries for realism
    dns_query1 = create_dns_query(CLIENT_IP, DNS_SERVER_IP, CLIENT_MAC, DNS_SERVER_MAC, "internal-server.local")
    packets.append(dns_query1)
    
    dns_resp1 = create_dns_response(CLIENT_IP, DNS_SERVER_IP, CLIENT_MAC, DNS_SERVER_MAC, 
                                     "internal-server.local", SERVER_IP, dns_query1[UDP].sport)
    packets.append(dns_resp1)
    
    # Additional DNS noise
    for domain in ["example.com", "google.com", "cdn.example.org"]:
        q = create_dns_query(CLIENT_IP, DNS_SERVER_IP, CLIENT_MAC, DNS_SERVER_MAC, domain)
        packets.append(q)
        r = create_dns_response(CLIENT_IP, DNS_SERVER_IP, CLIENT_MAC, DNS_SERVER_MAC, 
                                domain, f"93.184.{random.randint(1,255)}.{random.randint(1,255)}", q[UDP].sport)
        packets.append(r)
    
    # HTTP Session 1: GET request to homepage
    client_port = 54321
    handshake1, client_seq1, server_seq1 = create_tcp_handshake(
        CLIENT_IP, SERVER_IP, client_port, 80, CLIENT_MAC, SERVER_MAC, 100
    )
    packets.extend(handshake1)
    
    http_get, client_seq1 = create_http_request(
        CLIENT_IP, SERVER_IP, client_port, 80, CLIENT_MAC, SERVER_MAC,
        client_seq1, server_seq1, "GET", "/"
    )
    packets.append(http_get)
    
    homepage_body = '{"status":"ok","message":"Welcome to Internal Server","version":"1.0.0"}'
    http_resp1, server_seq1 = create_http_response(
        SERVER_IP, CLIENT_IP, 80, client_port, SERVER_MAC, CLIENT_MAC,
        server_seq1, client_seq1, "200 OK", homepage_body
    )
    packets.append(http_resp1)
    
    # HTTP Session 2: Login attempt (contains the secret)
    client_port2 = 54322
    handshake2, client_seq2, server_seq2 = create_tcp_handshake(
        CLIENT_IP, SERVER_IP, client_port2, 80, CLIENT_MAC, SERVER_MAC, 200
    )
    packets.extend(handshake2)
    
    login_body = "username=admin&password=supersecret123"
    http_post, client_seq2 = create_http_request(
        CLIENT_IP, SERVER_IP, client_port2, 80, CLIENT_MAC, SERVER_MAC,
        client_seq2, server_seq2, "POST", "/api/login", login_body
    )
    packets.append(http_post)
    
    # Response with the secret token (base64 encoded to prevent simple strings extraction)
    login_response = f'{{"status":"success","message":"Login successful","session_token":"{ENCODED_TOKEN}"}}'
    http_resp2, server_seq2 = create_http_response(
        SERVER_IP, CLIENT_IP, 80, client_port2, SERVER_MAC, CLIENT_MAC,
        server_seq2, client_seq2, "200 OK", login_response
    )
    packets.append(http_resp2)
    
    # HTTP Session 3: Some additional noise
    client_port3 = 54323
    handshake3, client_seq3, server_seq3 = create_tcp_handshake(
        CLIENT_IP, SERVER_IP, client_port3, 80, CLIENT_MAC, SERVER_MAC, 300
    )
    packets.extend(handshake3)
    
    http_get3, client_seq3 = create_http_request(
        CLIENT_IP, SERVER_IP, client_port3, 80, CLIENT_MAC, SERVER_MAC,
        client_seq3, server_seq3, "GET", "/api/dashboard"
    )
    packets.append(http_get3)
    
    dashboard_body = '{"status":"ok","data":{"user":"admin","role":"administrator","last_login":"2026-01-20T12:00:00Z"}}'
    http_resp3, server_seq3 = create_http_response(
        SERVER_IP, CLIENT_IP, 80, client_port3, SERVER_MAC, CLIENT_MAC,
        server_seq3, client_seq3, "200 OK", dashboard_body
    )
    packets.append(http_resp3)
    
    # Additional DNS queries for more realism
    for domain in ["api.internal.local", "metrics.local", "logs.internal.local"]:
        q = create_dns_query(CLIENT_IP, DNS_SERVER_IP, CLIENT_MAC, DNS_SERVER_MAC, domain)
        packets.append(q)
    
    # Write to PCAP file
    wrpcap(OUTPUT_FILE, packets)
    print(f"[+] Generated PCAP file: {OUTPUT_FILE}")
    print(f"[+] Total packets: {len(packets)}")
    print(f"[+] Secret token embedded in HTTP response")

if __name__ == "__main__":
    generate_pcap()
