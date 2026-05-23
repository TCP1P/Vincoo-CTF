#!/usr/bin/env python3
"""
Advanced Python sandbox escape challenge.
__builtins__ has been completely cleared.
Can you recover access to read the flag?
"""

import sys

def banner():
    print("""
╔═══════════════════════════════════════════════╗
║                                               ║
║                  PENJARA PLUS                 ║
║                                               ║
║  Nuh uh kali ini tidak semudah penjara itu.   ║
║  Semua akses telah kami dicabut.              ║
║                                               ║
║  Tidak ada yang bisa melarikan diri...        ║
║                                               ║
╚═══════════════════════════════════════════════╝
    """)

def main():
    banner()
    print("[*] Masukkan kode Python kamu:")
    print("[*] Ketik 'exit' untuk keluar.\n")
    
    while True:
        try:
            print(">>> ", end="", flush=True)
            user_input = sys.stdin.readline().strip()
            
            if not user_input:
                continue
            
            if user_input.lower() == "exit":
                print("[*] Sampai jumpa!")
                break
            
            # Execute with EMPTY builtins - no open, print, etc available
            try:
                result = eval(user_input, {"__builtins__": {}}, {})
                if result is not None:
                    print(result)
            except SyntaxError:
                exec(user_input, {"__builtins__": {}}, {})
            except Exception as e:
                print(f"[!] Error: {e}")
                
        except EOFError:
            break
        except KeyboardInterrupt:
            print("\n[*] Sampai jumpa!")
            break

if __name__ == "__main__":
    main()
