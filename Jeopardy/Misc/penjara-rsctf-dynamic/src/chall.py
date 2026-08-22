#!/usr/bin/env python3
"""
Simple Python sandbox escape challenge.
Can you break out of the restricted environment?
"""

import sys
import re

# Kata-kata yang diblokir (case-insensitive, whole word)
BLOCKED = ["open", "file"]

def check_input(code: str) -> bool:
    """Check if input contains any blocked keywords."""
    for word in BLOCKED:
        # Match whole word only (case-insensitive)
        if re.search(r'\b' + re.escape(word) + r'\b', code, re.IGNORECASE):
            print(f"[!] Kata terlarang terdeteksi: '{word}'")
            return False
    return True

def banner():
    print("""
╔═══════════════════════════════════════╗
║                                       ║
║               PENJARA                 ║
║                                       ║
║     Anda telah dikurung di sini.      ║
║     Tidak ada jalan keluar...         ║
║                                       ║
║     Atau mungkin ada?                 ║
║                                       ║
╚═══════════════════════════════════════╝
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

            if not check_input(user_input):
                continue

            # Execute with full builtins available
            try:
                result = eval(user_input)
                if result is not None:
                    print(result)
            except SyntaxError:
                exec(user_input)
            except Exception as e:
                print(f"[!] Error: {e}")

        except EOFError:
            break
        except KeyboardInterrupt:
            print("\n[*] Sampai jumpa!")
            break

if __name__ == "__main__":
    main()
