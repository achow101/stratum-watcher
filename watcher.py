#! /usr/bin/env python3

import argparse
import atexit
import json
import logging
import os
import socket
import struct
import sys
import time

from authproxy import AuthServiceProxy, JSONRPCException
from multiprocessing import Process
from urllib.parse import urlparse, urlunparse

# Setup logging
file_handler = logging.FileHandler(filename="stratum-watcher.log")
stdout_handler = logging.StreamHandler(sys.stdout)
logging.basicConfig(
    handlers=[file_handler, stdout_handler],
    format="%(asctime)s %(levelname)s: %(message)s",
)
LOG = logging.getLogger()
LOG.setLevel(logging.INFO)


class Watcher(Process):
    def __init__(self, url, userpass, rpccookiefile, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.buf = b""
        self.id = 0
        self.userpass = userpass
        self.signals = None
        self.last_log_time = time.time()

        # Parse the URL
        self.purl = urlparse(url)
        if self.purl.scheme != "stratum+tcp":
            raise ValueError(
                f"Unrecognized scheme {self.purl.scheme}, only 'stratum+tcp' is allowed"
            )
        if self.purl.hostname is None:
            raise ValueError(f"No hostname provided")
        if self.purl.port is None:
            raise ValueError(f"No port provided")
        if self.purl.path != "":
            raise ValueError(f"URL has a path {self.purl.path}, this is not valid")

        # Get the RPC cookie
        cookie_filepath = os.path.abspath(os.path.expanduser(rpccookiefile))
        with open(cookie_filepath, "r") as f:
            self.rpc_userpass = f.readline()

        # Open RPC connection
        self.rpc = AuthServiceProxy(f"http://{self.rpc_userpass}@localhost:8332")
        self.last_seen_blockhash = self.rpc.getbestblockhash()

        self.init_socket()

    def init_socket(self):
        # Make the socket
        self.sock = socket.socket()
        self.sock.settimeout(600)

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        LOG.debug(f"Disconnected from {urlunparse(self.purl)}")

    def get_msg(self):
        while True:
            split_buf = self.buf.split(b"\n", maxsplit=1)
            r = split_buf[0]
            try:
                resp = json.loads(r)

                # Remove r from the buffer
                if len(split_buf) == 2:
                    self.buf = split_buf[1]
                else:
                    self.buf = b""

                # Decoded, so return this message
                return resp
            except json.JSONDecodeError:
                # Failed to decode, maybe missing, so try to get more
                new_buf = self.sock.recv(4096)
                if len(new_buf) == 0:
                    raise EOFError("Socket EOF received")
                self.buf += new_buf

    def send_jsonrpc(self, method, params):
        # Build the jsonrpc request
        data = {
            "jsonrpc": "2.0",
            "id": self.id,
            "method": method,
            "params": params,
        }
        self.id += 1

        # Send the jsonrpc request
        LOG.debug(f"Sending: {data}")
        json_data = json.dumps(data) + "\n"
        self.sock.send(json_data.encode())

        # Get the jsonrpc reqponse
        resp = self.get_msg()
        LOG.debug(f"Received: {resp}")

    def get_stratum_work(self):
        # Open TCP connection to the server
        self.sock.connect((self.purl.hostname, self.purl.port))
        LOG.debug(f"Connected to server {urlunparse(self.purl)}")

        # Subscribe to mining notifications
        self.send_jsonrpc("mining.subscribe", ["StratumWatcher/0.1"])
        LOG.debug(f"Subscribed to pool notifications")

        # Authorize with the pool
        self.send_jsonrpc("mining.authorize", self.userpass.split(":"))
        LOG.debug(f"Authed with the pool")

        # Wait for notifications
        while True:
            try:
                n = self.get_msg()
            except Exception as e:
                LOG.debug(f"Received exception for {self.purl.hostname}: {e}")
                break
            LOG.debug(f"Received notification: {n}")

            # Check the notification for mining.notify
            if "method" in n and n["method"] == "mining.notify":
                # Get the previous block hash
                prev_bh_stratum = struct.unpack(
                    "<IIIIIIII", bytes.fromhex(n["params"][1])
                )
                prev_bh = struct.pack(
                    "<IIIIIIII",
                    prev_bh_stratum[7],
                    prev_bh_stratum[6],
                    prev_bh_stratum[5],
                    prev_bh_stratum[4],
                    prev_bh_stratum[3],
                    prev_bh_stratum[2],
                    prev_bh_stratum[1],
                    prev_bh_stratum[0],
                ).hex()

                # Check that this is Bitcoin
                if prev_bh != self.last_seen_blockhash:
                    # If the blockhash doesn't match what we've cached, ask bitcoind
                    try:
                        self.rpc.getblockheader(prev_bh)
                        self.last_seen_blockhash = prev_bh
                    except JSONRPCException:
                        LOG.debug(f"Received non-Bitcoin work, ignoring")
                        continue

                # Check for taproot versionbits
                block_ver_hex = n["params"][5]
                block_ver = int.from_bytes(
                    bytes.fromhex(block_ver_hex), byteorder="big"
                )
                if block_ver & (1 << 2):
                    if self.signals is None:
                        LOG.info(
                            f"✅ Signaling initially: {self.purl.hostname}:{self.purl.port}"
                        )
                        self.last_log_time = time.time()
                    elif not self.signals:
                        LOG.info(
                            f"✅ Now signaling: {self.purl.hostname}:{self.purl.port}"
                        )
                        self.last_log_time = time.time()
                    elif time.time() - self.last_log_time > 300:
                        LOG.info(
                            f"✅ Still signaling: {self.purl.hostname}:{self.purl.port}"
                        )
                        self.last_log_time = time.time()
                    LOG.debug(
                        f"Issued new work that SIGNALS ✅ for Taproot from {self.purl.hostname}:{self.purl.port}"
                    )
                    self.signals = True
                else:
                    if self.signals is None:
                        LOG.info(
                            f"❌ Not signaling initially: {self.purl.hostname}:{self.purl.port}"
                        )
                        self.last_log_time = time.time()
                    elif self.signals:
                        LOG.info(
                            f"❌ Stopped signaling: {self.purl.hostname}:{self.purl.port}"
                        )
                        self.last_log_time = time.time()
                    elif time.time() - self.last_log_time > 300:
                        LOG.info(
                            f"❌ Still not signaling: {self.purl.hostname}:{self.purl.port}"
                        )
                        self.last_log_time = time.time()
                    LOG.debug(
                        f"Issued new work that DOES NOT SIGNAL ❌ for Taproot from {self.purl.hostname}:{self.purl.port}"
                    )
                    self.signals = False

    def run(self):
        # If there is a socket exception, retry
        while True:
            try:
                self.get_stratum_work()
            except (ConnectionRefusedError, EOFError, socket.timeout):
                pass
            self.close()
            self.init_socket()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Subscribe to a Stratum and listen for new work"
    )
    parser.add_argument("url", help="The URL of the stratum server")
    parser.add_argument(
        "userpass", help="Username and password combination separated by a colon (:)"
    )
    parser.add_argument("--debug", help="Verbose debug logging", action="store_true")
    parser.add_argument("--logfile", help="Log file to log to")
    parser.add_argument(
        "--rpccookiefile",
        help="Cookie file for Bitcoin Core RPC creds",
        default="~/.bitcoin/.cookie",
    )
    args = parser.parse_args()

    # Set logging level
    loglevel = logging.DEBUG if args.debug else logging.INFO
    LOG.setLevel(loglevel)

    # Set the log file
    if args.logfile is not None:
        LOG.removeHandler(file_handler)
        logfile_handler = logging.FileHandler(filename=args.logfile)
        LOG.addHandler(logfile_handler)

    try:
        while True:
            w = Watcher(args.url, args.userpass, args.rpccookiefile)
            atexit.register(w.close)
            w.get_stratum_work()
            atexit.unregister(w.close)
    except KeyboardInterrupt:
        # When receiving a keyboard interrupt, do nothing and let atexit clean things up
        pass
