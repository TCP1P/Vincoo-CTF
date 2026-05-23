#!/bin/sh
socat tcp-l:9998,reuseaddr,fork exec:"python3 chall.py"
