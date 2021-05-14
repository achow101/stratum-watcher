#! /usr/bin/env python3

import argparse
import atexit
import json
import logging
import socket
import sys
import time

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
    def __init__(self, url, userpass, *args, **kwargs):
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
        LOG.info(f"Disconnected from {urlunparse(self.purl)}")

    def get_msg(self):
        while True:
            new_buf = self.sock.recv(4096)
            if len(new_buf) == 0:
                raise EOFError("Socket EOF received")
            self.buf += new_buf
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
                pass

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
            except (ConnectionRefusedError, EOFError):
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
    args = parser.parse_args()

    # Set logging level
    loglevel = logging.DEBUG if args.debug else logging.INFO
    LOG.setLevel(loglevel)

    try:
        while True:
            w = Watcher(args.url, args.userpass)
            atexit.register(w.close)
            w.get_stratum_work()
            atexit.unregister(w.close)
    except KeyboardInterrupt:
        # When receiving a keyboard interrupt, do nothing and let atexit clean things up
        pass
