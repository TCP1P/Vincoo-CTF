import os
import shutil
import subprocess
import sys
from typing import List

LOG_FILE = "server.log"
ZIP_FILE = "flag.zip"
TARGET_ENDPOINT = "/api/secret"

def get_latencies(log_path: str, target: str) -> List[int]:
    latencies = []
    try:
        with open(log_path, "r") as f:
            for line in f:
                if target in line:
                    parts = line.split()
                    try:
                        latencies.append(int(parts[-1]))
                    except (ValueError, IndexError):
                        continue
    except FileNotFoundError:
        print(f"Error: {log_path} not found.")
        sys.exit(1)
    return latencies

def calculate_dynamic_threshold(latencies: List[int]) -> int:
    if not latencies:
        return 0
    
    sorted_lats = sorted(latencies)
    max_gap = 0
    threshold = 0
    
    for i in range(len(sorted_lats) - 1):
        gap = sorted_lats[i+1] - sorted_lats[i]
        if gap > max_gap:
            max_gap = gap
            threshold = (sorted_lats[i] + sorted_lats[i+1]) // 2
            
    return threshold

def extract_password(latencies: List[int], threshold: int) -> str:
    """Converts latencies to bits and then to a password string."""
    bits = ['1' if lat > threshold else '0' for lat in latencies]
    bit_string = "".join(bits)
    
    password = []
    for i in range(0, len(bit_string), 8):
        byte = bit_string[i:i+8]
        if len(byte) == 8:
            password.append(chr(int(byte, 2)))
            
    return "".join(password)

def extract_archive(password: str):
    print("Attempting to unlock archive...")
    
    if os.path.exists(ZIP_FILE):
        if shutil.which("7z"):
            subprocess.run(["7z", "x", f"-p{password}", "-y", ZIP_FILE], check=False)
        elif shutil.which("unzip"):
            subprocess.run(["unzip", "-P", password, "-o", ZIP_FILE], check=False)
        else:
            print("No unzip tool found. Please manually unzip.")
    elif os.path.exists("flag.enc"):
        print("Found flag.enc, attempting XOR decryption...")
        try:
            with open("flag.enc", "rb") as f:
                enc_data = f.read()
            pass_bytes = password.encode()
            decrypted = bytearray(b ^ pass_bytes[i % len(pass_bytes)] for i, b in enumerate(enc_data))
            print(f"Decrypted content: {decrypted.decode(errors='ignore')}")
        except Exception as e:
            print(f"Decryption failed: {e}")

def solve():
    print("Reading log file...")
    latencies = get_latencies(LOG_FILE, TARGET_ENDPOINT)
    
    if not latencies:
        print("No traffic found for target endpoint.")
        return

    print(f"Found {len(latencies)} requests to secret endpoint.")
    
    # Dynamic thresholding
    threshold = calculate_dynamic_threshold(latencies)
    print(f"Calculated dynamic threshold: {threshold} ms")
    
    password = extract_password(latencies, threshold)
    print(f"Recovered Password: {password}")
    
    extract_archive(password)

if __name__ == "__main__":
    solve()