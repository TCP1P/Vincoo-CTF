#!/bin/sh
set -eu

# Fork per connection.
exec socat TCP-LISTEN:8011,reuseaddr,fork EXEC:"python3 -u /home/ctf/chall/server.py",stderr
