#!/bin/sh
socat tcp-l:9999,reuseaddr,fork exec:"python3 chall.py"
