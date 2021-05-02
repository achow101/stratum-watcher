#! /usr/bin/env python3

import argparse
import subprocess
import signal

POOLS = [
    ["stratum+tcp://us-east.stratum.slushpool.com:3333", "achow101.worker1:pass"],
    ["stratum+tcp://btc.viabtc.com:3333", "achow101.001:123"],
    ["stratum+tcp://btc-na.f2pool.com:3333", "achow102.001:21235365876986800"],
    ["stratum+tcp://stratum.1thash.btc.top:8888", "achow102.wentaproot:wentaproot"],
    ["stratum+tcp://us.ss.btc.com:1800", "achow101.wentaproot:wentaproot"],
    ["stratum+tcp://ss.antpool.com:3333", "achow101.wentaproot:wentaproot"],
    ["stratum+tcp://stratum.kano.is:3333", "achow101.wentaproot:x"],
    [
        "stratum+tcp://solo.ckpool.org:3333",
        "bc1qmuf9u75g745955f67c85nd33pdyh4v8zzr2lms.wentaproot:x",
    ],
    ["stratum+tcp://btc.ss.poolin.com:443", "achow101.001:123"],
    ["stratum+tcp://stratum.btc.top:8888", "achow101.001:123"],
]

parser = argparse.ArgumentParser(
    description="Run the watcher.py script for multiple hardcoded pools"
)
parser.add_argument("--debug")
args = parser.parse_args()

procs = []

# Start all of the scripts
for pool in POOLS:
    proc_args = ["python", "./watcher.py"]
    if args.debug:
        proc_args.append("--debug")
    proc_args.extend(pool)

    proc = subprocess.Popen(proc_args)
    procs.append(proc)

signal.signal(signal.SIGINT, signal.SIG_IGN)

# Interrupt and wait for all of the processes to end
for p in procs:
    p.wait()
