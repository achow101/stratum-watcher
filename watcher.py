#! /usr/bin/env python3

import argparse
import json
import logging
import socket
import sys

from urllib.parse import urlparse

ID = 0
BUF = b""

# Setup logging
file_handler = logging.FileHandler(filename="stratum-watcher.log")
stdout_handler = logging.StreamHandler(sys.stdout)
logging.basicConfig(handlers=[file_handler, stdout_handler])
LOG = logging.getLogger()


def get_msg(sock):
    global BUF
    while True:
        BUF += sock.recv(4096)
        split_buf = BUF.split(b"\n", maxsplit=1)
        r = split_buf[0]
        try:
            resp = json.loads(r)

            # Remove r from the buffer
            if len(split_buf) == 2:
                BUF = split_buf[1]
            else:
                BUF = b""

            # Decoded, so return this message
            return resp
        except:
            # Failed to decode, maybe missing, so try to get more
            pass


def send_jsonrpc(sock, method, params):
    # Build the jsonrpc request
    global ID
    data = {
        "jsonrpc": "2.0",
        "id": ID,
        "method": method,
        "params": params,
    }
    ID += 1

    # Send the jsonrpc request
    LOG.debug(f"Sending: {data}")
    json_data = json.dumps(data) + "\n"
    sock.send(json_data.encode())

    # Get the jsonrpc reqponse
    resp = get_msg(sock)
    LOG.debug(f"Received: {resp}")


def get_stratum_work(url, userpass):
    # Parse the URL
    parsed = urlparse(url)
    if parsed.scheme != "stratum+tcp":
        raise ValueError(
            f"Unrecognized scheme {parsed.scheme}, only 'stratum+tcp' is allowed"
        )
    if parsed.hostname is None:
        raise ValueError(f"No hostname provided")
    if parsed.port is None:
        raise ValueError(f"No port provided")
    if parsed.path != "":
        raise ValueError(f"URL has a path {parsed.path}, this is not valid")

    # Open TCP connection to the server
    stratum_sock = socket.socket()
    stratum_sock.connect((parsed.hostname, parsed.port))
    LOG.info(f"Connecting to server {url}")

    # Subscribe to mining notifications
    send_jsonrpc(stratum_sock, "mining.subscribe", ["StratumWatcher/0.1"])
    LOG.debug(f"Subscribed to pool notifications")

    # Authorize with the pool
    send_jsonrpc(stratum_sock, "mining.authorize", userpass.split(":"))
    LOG.debug(f"Authed with the pool")

    # Wait for notifications
    while True:
        n = get_msg(stratum_sock)
        LOG.debug(f"Received notification: {n}")


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

get_stratum_work(args.url, args.userpass)
