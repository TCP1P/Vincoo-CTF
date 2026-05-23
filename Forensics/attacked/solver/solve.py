#!/usr/bin/env python3
"""
Solver for attacked challenge.
Connects to the quiz service and answers all questions correctly.
"""

from pwn import *

# Configuration
HOST = "localhost"
PORT = 9012

# Answers derived from analyzing access.log
ANSWERS = [
    "192.168.1.100",  # Q1: Attacker IP
    "cmd.php",         # Q2: Webshell filename
    "file",            # Q3: Vulnerable LFI parameter
    "46",              # Q4: Total requests from attacker IP
    "robots.txt"       # Q5: First endpoint after homepage
]


def solve():
    """Connect to the quiz service and answer all questions."""
    conn = remote(HOST, PORT)
    
    # Receive banner
    conn.recvuntil(b"flag!")
    conn.recvuntil(b"\n")
    
    # Answer each question
    for i, answer in enumerate(ANSWERS):
        # Wait for question prompt
        conn.recvuntil(b"> ")
        
        # Send answer
        log.info(f"Q{i+1}: Sending answer '{answer}'")
        conn.sendline(answer.encode())
        
        # Check response
        response = conn.recvline().decode()
        if "Benar" in response:
            log.success(f"Q{i+1}: Correct!")
        else:
            log.error(f"Q{i+1}: Wrong answer!")
            conn.close()
            return
    
    # Receive flag
    conn.recvuntil(b"Flag: ")
    flag = conn.recvline().decode().strip()
    
    log.success(f"Flag: {flag}")
    conn.close()
    
    return flag


if __name__ == "__main__":
    solve()
