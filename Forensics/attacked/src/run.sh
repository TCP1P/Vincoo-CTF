#!/bin/bash
cd /home/ctf/chall/src
socat TCP-LISTEN:9012,reuseaddr,fork EXEC:"python3 chall.py",stderr
