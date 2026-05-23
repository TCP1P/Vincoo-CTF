#!/usr/bin/env python3
"""
Solver for the PCAP forensics challenge.

This script extracts the flag from the network capture file by analyzing HTTP traffic.
The flag is base64 encoded in the session_token field.
"""

from scapy.all import *
import re
import sys
import base64
import json

def solve(pcap_file="../dist/capture.pcap"):
    """
    Extract the flag from the PCAP file.
    
    Solution approach:
    1. Read the PCAP file
    2. Filter for TCP packets with HTTP data
    3. Find the session_token in JSON response
    4. Base64 decode the token to get the flag
    """
    
    print(f"[*] Reading PCAP file: {pcap_file}")
    
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[-] Error: File not found: {pcap_file}")
        sys.exit(1)
    
    print(f"[*] Total packets loaded: {len(packets)}")
    
    found_flag = None
    
    for i, pkt in enumerate(packets):
        # Check if packet has Raw layer (contains payload data)
        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                
                # Look for HTTP response with session_token
                if 'session_token' in payload and 'HTTP/1.1 200' in payload:
                    print(f"[+] Found login response in packet #{i}")
                    
                    # Show connection info
                    if pkt.haslayer(TCP) and pkt.haslayer(IP):
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                        print(f"[*] Source: {src_ip}:{src_port}")
                        print(f"[*] Destination: {dst_ip}:{dst_port}")
                    
                    # Extract JSON body from HTTP response
                    json_match = re.search(r'\{[^{}]*"session_token"[^{}]*\}', payload)
                    if json_match:
                        json_str = json_match.group(0)
                        print(f"[*] JSON Response: {json_str}")
                        
                        try:
                            data = json.loads(json_str)
                            encoded_token = data.get('session_token', '')
                            
                            if encoded_token:
                                print(f"[*] Encoded token: {encoded_token}")
                                
                                # Base64 decode the token
                                decoded_flag = base64.b64decode(encoded_token).decode()
                                found_flag = decoded_flag
                                print(f"\n[+] Decoded FLAG: {found_flag}")
                                break
                        except json.JSONDecodeError:
                            print("[-] Failed to parse JSON")
                        except Exception as e:
                            print(f"[-] Error decoding: {e}")
                    
            except Exception as e:
                continue
    
    if found_flag:
        return found_flag
    else:
        print("[-] Flag not found in PCAP file")
        return None

def main():
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    else:
        pcap_file = "../dist/capture.pcap"
    
    flag = solve(pcap_file)
    
    if flag:
        # Verify flag format
        expected_flag = "SnapanCTF{s3l4m4t7t7t7t_4nd4_b4ru_s4j4_m3ng4n4l1s1s_n37w0rk_c4p7ur3}"
        if flag == expected_flag:
            print("[+] Flag verified correctly!")
        else:
            print(f"[!] Warning: Flag mismatch")
            print(f"    Expected: {expected_flag}")
            print(f"    Got: {flag}")

if __name__ == "__main__":
    main()
