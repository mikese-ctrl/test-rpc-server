#!/usr/bin/env python3

import socket
import struct
import threading
from impacket.uuid import uuidtup_to_bin

# NRPC UUID
NETLOGON_UUID = uuidtup_to_bin((
    "12345678-1234-abcd-ef00-01234567cffb",
    "1.0"
))

# Commonly documented opnum for NetrLogonSamLogonWithFlags
NETR_LOGON_SAM_LOGON_WITH_FLAGS = 45

BIND_ACK = bytes.fromhex(
    # RPC Version
    "05000c03"
    # flags/data rep/frag/auth
    "10000000"
    "48000000"
    "00000000"
    # max xmit/max recv
    "b810b810"
    # assoc group
    "00000000"
    # sec addr len
    "0000"
    # alignment
    "0000"
    # results
    "0100"
    "0000"
    "045d888aeb1cc9119fe808002b104860"
    "02000000"
)

# Simple RPC fault packet
RPC_FAULT = bytes.fromhex(
    "05000303"
    "10000000"
    "24000000"
    "00000000"
    "1c000000"
    "05000000"
    "1c000000"
    "00000000"
)

def parse_request(data):
    """
    Minimal parser for demo purposes only.
    """

    if len(data) < 24:
        return

    version = data[0]
    packet_type = data[2]

    print(f"[+] RPC Version: {version}")
    print(f"[+] Packet Type: {packet_type}")

    # Request PDU
    if packet_type == 0:
        if len(data) < 26:
            return

        opnum = struct.unpack("<H", data[22:24])[0]

        print(f"[+] RPC Request Opnum: {opnum}")

        if opnum == NETR_LOGON_SAM_LOGON_WITH_FLAGS:
            print("[+] Detected NetrLogonSamLogonWithFlags")

            stub = data[24:]

            print(f"[+] Stub length: {len(stub)}")
            print(f"[+] Stub preview: {stub[:64].hex()}")

def client_thread(sock, addr):
    print(f"[+] Connection from {addr}")

    try:
        while True:
            data = sock.recv(8192)

            if not data:
                break

            packet_type = data[2]

            # Bind request
            if packet_type == 11:
                print("[+] RPC bind request")
                sock.send(BIND_ACK)
                continue

            parse_request(data)

            # Deterministic safe failure
            sock.send(RPC_FAULT)

    except Exception as e:
        print(f"[!] Error: {e}")

    finally:
        sock.close()

def main():
    bind_ip = "0.0.0.0"
    bind_port = 4455

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((bind_ip, bind_port))
    server.listen(10)

    print(f"[+] Listening on {bind_ip}:{bind_port}")

    while True:
        client, addr = server.accept()

        t = threading.Thread(
            target=client_thread,
            args=(client, addr),
            daemon=True
        )
        t.start()

if __name__ == "__main__":
    main()
