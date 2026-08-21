#!/bin/sh
set -eu

: "${RSCTF_FLAG:?RSCTF_FLAG is required}"
umask 077
printf '%s\n' "$RSCTF_FLAG" > /home/ctf/flag.txt
unset RSCTF_FLAG

exec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 -u server.py"
