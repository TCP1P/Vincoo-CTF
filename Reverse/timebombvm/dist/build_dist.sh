#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

echo "[+] Building dist/timebombvm using Docker (alpine musl static)"

docker run --rm \
  -v "$ROOT_DIR":/work \
  -w /work/src/vm \
  alpine:3.19 \
  sh -lc 'apk add --no-cache build-base && make clean && make'

echo "[+] Done: $ROOT_DIR/dist/timebombvm"
