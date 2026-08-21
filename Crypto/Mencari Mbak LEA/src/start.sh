#!/bin/sh
set -eu

: "${GZCTF_FLAG:?GZCTF_FLAG is required}"
umask 077
printf '%s\n' "$GZCTF_FLAG" > /home/ctf/flag.txt
unset GZCTF_FLAG

exec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 -u server.py"
