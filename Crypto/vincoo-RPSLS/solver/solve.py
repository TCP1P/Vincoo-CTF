from pwn import *
import sys

MASK = 0xFFFFFFFF
N = 32
M = 7
MATRIX_A = 0x9908B0DF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF

class FakeMT:
    def __init__(self, seed):
        self.state = [0] * N
        self.index = N
        self.state[0] = seed & MASK
        for i in range(1, N):
            self.state[i] = (1812433253 * (self.state[i-1] ^ (self.state[i-1] >> 30)) + i) & MASK
        self.twist() 

    def twist(self):
        for i in range(N):
            x = (self.state[i] & UPPER_MASK) | (self.state[(i+1) % N] & LOWER_MASK)
            xa = x >> 1
            if x & 1:
                xa ^= MATRIX_A
            self.state[i] = self.state[(i + M) % N] ^ xa
        self.index = 0

    def extract_number(self):
        if self.index >= N:
            self.twist()
        y = self.state[self.index]
        self.index += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & MASK
    
    def get_move(self):
        return self.extract_number() % 5

HOST = 'localhost'
PORT = 8011

WIN_MAP = {0: [2, 3], 1: [0, 4], 2: [1, 3], 3: [1, 4], 4: [0, 2]}
MOVES = ["Rock", "Paper", "Scissors", "Lizard", "Spock"]

def get_winning_move(server_move):
    for my_move, losers in WIN_MAP.items():
        if server_move in losers:
            return my_move
    return 0

def solve():
    io = remote(HOST, PORT)
    
    observed_moves = []
    print("[*] Collecting 100 samples...")
    
    for i in range(100):
        io.sendlineafter(b'Input (0-4): ', b'0')
        io.recvuntil(b'Server played: ')
        move_name = io.recvline().strip().decode()
        observed_moves.append(MOVES.index(move_name))
    
    print("[*] Brute forcing seed (0 - 16,777,215)...")
    found_seed = None
    
    for seed in range(0xFFFFFF + 1):
        if seed % 500000 == 0:
            sys.stdout.write(f"\rScanning: {seed}")
            sys.stdout.flush()

        rng = FakeMT(seed)
        match = True
        
        for i in range(8):
            if rng.get_move() != observed_moves[i]:
                match = False
                break
        
        if match:
            for i in range(8, 100):
                 if rng.get_move() != observed_moves[i]:
                    match = False
                    break
            
            if match:
                found_seed = seed
                break

    print()
    
    if found_seed is None:
        print("[-] Seed not found.")
        io.close()
        return

    print(f"[+] Seed found: {found_seed}")
    rng = FakeMT(found_seed)
    
    for _ in range(100):
        rng.get_move()

    print("[*] Winning next 200 rounds...")
    
    for i in range(200):
        next_server_move = rng.get_move()
        my_move = get_winning_move(next_server_move)
        io.sendlineafter(b'Input (0-4): ', str(my_move).encode())
        io.recvline() 

    io.recvuntil(b'Congratz!')
    io.recvline()
    flag = io.recvline().strip().decode()
    print(f"[+] FLAG: {flag}")
    
    io.close()

if __name__ == "__main__":
    solve()