#! /usr/bin/env python3

import argparse
import signal

from watcher import Watcher

POOLS = [
    ["stratum+tcp://stratum.slushpool.com:3333", "achow101.worker1:pass"],
    ["stratum+tcp://eu.stratum.slushpool.com:3333", "achow101.worker1:pass"],
    ["stratum+tcp://us-east.stratum.slushpool.com:3333", "achow101.worker1:pass"],
    ["stratum+tcp://ca.stratum.slushpool.com:3333", "achow101.worker1:pass"],
    ["stratum+tcp://sg.stratum.slushpool.com:3333", "achow101.worker1:pass"],
    ["stratum+tcp://jp.stratum.slushpool.com:3333", "achow101.worker1:pass"],
    ["stratum+tcp://ru-west.stratum.slushpool.com:3333", "achow101.worker1:pass"],
    ["stratum+tcp://btc.viabtc.com:3333", "achow101.001:123"],
    ["stratum+tcp://btc.f2pool.com:3333", "achow102.001:21235365876986800"],
    ["stratum+tcp://btc-na.f2pool.com:3333", "achow102.001:21235365876986800"],
    ["stratum+tcp://btc-eu.f2pool.com:3333", "achow102.001:21235365876986800"],
    ["stratum+tcp://stratum.1thash.btc.top:8888", "achow102.wentaproot:wentaproot"],
    ["stratum+tcp://bak.1thash.btc.top:3333", "achow102.wentaproot:wentaproot"],
    ["stratum+tcp://us.ss.btc.com:1800", "achow101.wentaproot:wentaproot"],
    ["stratum+tcp://cn.ss.btc.com:1800", "achow101cn.wentaproot:wentaproot"],
    ["stratum+tcp://sz.ss.btc.com:1800", "achow101sz.wentaproot:wentaproot"],
    ["stratum+tcp://eu.ss.btc.com:1800", "achow101eu.wentaproot:wentaproot"],
    ["stratum+tcp://ss.antpool.com:3333", "achow101.wentaproot:wentaproot"],
    ["stratum+tcp://stratum.kano.is:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://or.kano.is:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://nya.kano.is:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://nl.kano.is:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://sg.kano.is:3333", "achow101.wentaproot:x"],
    [
        "stratum+tcp://solo.ckpool.org:3333",
        "bc1qmuf9u75g745955f67c85nd33pdyh4v8zzr2lms.wentaproot:x",
    ],
    ["stratum+tcp://btc.ss.poolin.com:443", "achow101.001:123"],
    ["stratum+tcp://btc-bj.ss.poolin.com:443", "achow101.001:123"],
    ["stratum+tcp://btc-cd.ss.poolin.com:443", "achow101.001:123"],
    ["stratum+tcp://btc-va.ss.poolin.com:443", "achow101.001:123"],
    ["stratum+tcp://btc-fra.ss.poolin.com:443", "achow101.001:123"],
    ["stratum+tcp://stratum.btc.top:8888", "achow101.001:123"],
    ["stratum+tcp://bak.btc.top:3333", "achow101.001:123"],
    ["stratum+tcp://ru1.btc.sigmapool.com:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://ru2.btc.sigmapool.com:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://ru3.btc.sigmapool.com:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://us1.btc.sigmapool.com:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://us2.btc.sigmapool.com:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://eu1.btc.sigmapool.com:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://eu2.btc.sigmapool.com:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://eu3.btc.sigmapool.com:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://cn1.btc.sigmapool.com:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://btc.luxor.tech:700", "achow101.wentaproot:x"],
    ["stratum+tcp://btc-us.luxor.tech:6000", "achow101.wentaproot:x"],
    ["stratum+tcp://btc-asia.luxor.tech:6000", "achow101.wentaproot:x"],
    ["stratum+tcp://btc-eu.luxor.tech:6000", "achow101.wentaproot:x"],
    ["stratum+tcp://bs.poolbinance.com:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://bn.huobipool.com:1800", "achow101.wentaproot:x"],
    ["stratum+tcp://bs.huobipool.com:1800", "achow101.wentaproot:x"],
    ["stratum+tcp://stratum.poolhb.com:8888", "achow101.wentaproot:x"],
    ["stratum+tcp://bm.huobipool.com:1800", "achow101.wentaproot:x"],
    ["stratum+tcp://bu.huobipool.com:1800", "achow101.wentaproot:x"],
    ["stratum+tcp://hk.huobipool.com:8888", "achow101.wentaproot:x"],
    ["stratum+tcp://gate.emcd.io:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://eu.emcd.io:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://cn.emcd.io:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://us.emcd.io:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://ir.emcd.io:3333", "achow101.wentaproot:x"],
    ["stratum+tcp://kz.emcd.io:3333", "achow101.wentaproot:x"],
]

parser = argparse.ArgumentParser(
    description="Run the watcher.py script for multiple hardcoded pools"
)
parser.add_argument("--debug")
args = parser.parse_args()

procs = []

# Handler for SIGINT that stops all of the processes
def sigint_handler(signal, frame):
    global procs
    for p in procs:
        p.close()
        p.terminate()


# Start all watcher processes
signal.signal(signal.SIGINT, signal.SIG_IGN)
for pool in POOLS:
    proc = Watcher(pool[0], pool[1], name=f"Watcher {pool[0]}")
    proc.start()
    procs.append(proc)

signal.signal(signal.SIGINT, sigint_handler)

# Interrupt and wait for all of the processes to end
for p in procs:
    p.join()
