#!/usr/bin/env python3
"""Idempotently route jimmyresearch.com/provena/* to the trial hub (strip the prefix).

Run as root on the server: python3 caddy-provena.py [/etc/caddy/Caddyfile]; then
`caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy`.
A backup is written next to the file first.
"""
import shutil
import sys
import time
from pathlib import Path

path = Path(sys.argv[1] if len(sys.argv) > 1 else "/etc/caddy/Caddyfile")
text = path.read_text()
if "@provena path /provena /provena/*" in text:
    print("already present")
    sys.exit(0)
site = text.index("jimmyresearch.com, www.jimmyresearch.com {")
# same pattern as /safe, placed just before it
anchor = text.index("\t@safeguard path /safe /safe/*", site)
block = ("\t@provena path /provena /provena/*\n\thandle @provena {\n\t\turi strip_prefix /provena\n"
         "\t\treverse_proxy localhost:8803\n\t}\n\n")
shutil.copy2(path, path.with_name(path.name + f".bak-provena-{time.strftime('%Y%m%d-%H%M%S')}"))
path.write_text(text[:anchor] + block + text[anchor:])
print("added the /provena route")
