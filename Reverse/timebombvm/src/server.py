#!/usr/bin/env python3
import re
import secrets
import select
import sys
import time

import tbvm

ROUNDS = 5
TIME_LIMIT_S = 1.200
# small slack for normal WAN jitter. Narrative stays 1200ms.
SOFT_SLACK_S = 0.065

HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _w(s: str) -> None:
    sys.stdout.write(s)
    sys.stdout.flush()


def _rline(timeout_s: float) -> tuple[str | None, float]:
    """Read one line with timeout. Returns (line or None, elapsed seconds)."""
    t0 = time.monotonic()
    ready, _, _ = select.select([sys.stdin], [], [], timeout_s)
    if not ready:
        return None, time.monotonic() - t0
    line = sys.stdin.readline()
    return line, time.monotonic() - t0


def main() -> int:
    _w(
        "=== TimeBomb VM ===\n"
        "5 rounds | strict input deadline: 1200ms/round\n"
        "Protocol: receive SEED + encrypted BYTECODE, respond token (64 hex)\n"
        "Miss the timer, bye.\n\n"
    )

    for i in range(1, ROUNDS + 1):
        seed = secrets.randbits(32)
        rr = tbvm.make_round(seed, i)

        _w(f"[Round {i}/{ROUNDS}]\n")
        _w(f"SEED: {seed:08x}\n")
        _w(f"BC_LEN: {rr.bc_len}\n")
        _w(f"BYTECODE_B64: {rr.bc_b64}\n")
        _w(f"CYCLE_BUDGET: {rr.cycle_budget}\n")
        _w("> ")

        # Only start the deadline AFTER prompt flush.
        line, dt = _rline(TIME_LIMIT_S + SOFT_SLACK_S)
        if line is None or dt > TIME_LIMIT_S + SOFT_SLACK_S:
            _w("[TIMEOUT] 1200ms exceeded. congrats kamu kalah sama timer. bye.\n")
            return 0

        token = line.strip()
        if not HEX64_RE.fullmatch(token):
            _w("[WRONG] token mismatch. bye.\n")
            return 0

        if token.lower() != rr.expected_token_hex:
            _w("[WRONG] token mismatch. bye.\n")
            return 0

        ms = int(dt * 1000)
        _w(f"[OK] {i}/{ROUNDS} accepted. (t={ms}ms)\n\n")

    flag = open("flag.txt", "r", encoding="utf-8").read().strip()
    _w(flag + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
