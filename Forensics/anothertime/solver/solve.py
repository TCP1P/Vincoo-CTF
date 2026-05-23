import re
from scapy.all import *

def solve():
    print("[*] Reading capture.pcap...")
    packets = rdpcap("capture.pcap")
    
    target_ip = None
    target_port = 0
    
    # Step 1: Cari Clue
    print("[*] Scanning for beacon/clue...")
    for p in packets:
        if p.haslayer(TCP) and p.haslayer(Raw):
            try:
                payload = p[Raw].load.decode('utf-8', errors='ignore')
                if "Target:" in payload:
                    # Misal: ... [Target: 10.0.0.88:1337] ...
                    match = re.search(r"Target: (\d+\.\d+\.\d+\.\d+):(\d+)", payload)
                    if match:
                        target_ip = match.group(1)
                        target_port = int(match.group(2))
                        print(f"[+] Found Target: {target_ip}:{target_port}")
                        break
            except Exception as e:
                pass
                
    if not target_ip:
        print("[-] Failed to find target IP clue.")
        return

    part1 = ""
    part2 = ""
    
    # Step 2: Ekstrak Data
    print(f"[*] Extracting data from traffic associated with {target_ip}...")
    
    known_connections = set() # Track connections to avoid duplicates if any (though logic handles this)
    
    # rekonstruksi nya harus di sort berdasarkan waktu, tp biasanya packet Scapy udh ke sort.
    
    for p in packets:
        if not p.haslayer(IP) or not p.haslayer(TCP):
            continue
            
        # Part 1: Client -> Server 
        # ada di : IP ID high byte
        if p[IP].dst == target_ip and p[TCP].dport == target_port:
            if p[TCP].flags == "S":
                # Cek ISN / IP ID
                ip_id = p[IP].id
                char_val = (ip_id >> 8) & 0xFF
                # Filter noice garbage (flag pasti ASCII)
                if 32 <= char_val <= 126:
                    part1 += chr(char_val)
                # print(f"DEBUG: C->S IP.id={ip_id:04x} char={chr(char_val) if 32<=char_val<=126 else '.'}")

        # Part 2: Server (Target) -> Client
        # ada di : ISN top 8 bits of SYN/ACK
        if p[IP].src == target_ip and p[TCP].sport == target_port:
            if p[TCP].flags == "SA": # SYN/ACK
                isn = p[TCP].seq
                char_val = (isn >> 24) & 0xFF
                if 32 <= char_val <= 126:
                    part2 += chr(char_val)
                # print(f"DEBUG: S->C ISN={isn:08x} char={chr(char_val) if 32<=char_val<=126 else '.'}")

    print(f"[+] Part 1 (IP ID): {part1}")
    print(f"[+] Part 2 (TCP ISN): {part2}")
    
    full_flag = part1 + part2
    print(f"[+] Full Flag: {full_flag}")
    
    if full_flag == "VincooCTF{t1m1ng_1s_everything_!}":
        print("[SUCCESS] Flag matches expected value!")
    else:
        print("[FAIL] Flag mismatch or incomplete.")

if __name__ == "__main__":
    solve()
