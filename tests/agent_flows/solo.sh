#!/usr/bin/env bash
# Lane A: a solo research agent records, proves and verifies — without a terminal.
source "$(dirname "$0")/common.sh"
export PROVENA_HOME=$W/home
expect 0 $P keygen --kind software
mkdir "$W/p" && cd "$W/p"
expect 0 $P init --name solo
echo "measure X" > protocol.md; mkdir raw; echo "1,2" > raw/d.csv
echo 'import sys; print(sum(map(int, open(sys.argv[1]).read().split(","))))' > a.py
expect 0 $P plan protocol.md
expect 0 $P add raw/d.csv
expect 0 $P run --plan protocol.md -- python3 a.py raw/d.csv      # inputs from the command line
expect 3 $P run --out res -- python3 -c 'raise SystemExit(3)'     # failed, wrote nothing: recorded
expect 2 $P add /etc/hosts                                          # outside the project
expect 2 $P add raw                                                 # a directory
expect 2 $P keygen --name ../evil
expect 0 $P prove protocol.md -o p.pvb
expect 0 $P verify p.pvb --json
expect 0 $P verify
( unset PROVENA_PASSPHRASE_FILE; expect 4 $P log )                 # no passphrase, no terminal
echo "solo flow OK"
