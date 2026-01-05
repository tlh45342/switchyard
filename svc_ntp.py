# svc_ntp.py

# Copyright 2025 Thomas L Hamilton
# 
# Licensed under the Apache License, Version 2.0 (the "License"); 
# you may not use this file except in compliance with the License. 
# You may obtain a copy of the License at 
# 
#     http://www.apache.org/licenses/LICENSE-2.0

from __future__ import annotations

import asyncio
import time
import struct

from switchyard import (
    SwitchyardClient,
    parse_eth, parse_ipv4, parse_udp, parse_arp,
    build_udp, build_ipv4, build_eth,
    build_arp_reply,
    ETH_TYPE_IPV4, ETH_TYPE_ARP, IPPROTO_UDP,
    ARP_OP_REQUEST,
)

NTP_ENDPOINT_NAME = "svc_ntp"
NTP_IP = "10.0.0.3"
NTP_PORT = 123

NTP_EPOCH_DELTA = 2208988800  # seconds between 1900-01-01 and 1970-01-01

def unix_to_ntp_ts(t: float) -> tuple[int, int]:
    sec = int(t) + NTP_EPOCH_DELTA
    frac = int((t - int(t)) * (1 << 32)) & 0xFFFFFFFF
    return sec & 0xFFFFFFFF, frac

def build_ntp_response(req: bytes) -> bytes:
    # NTP packet is 48 bytes.
    # We'll do minimal fields:
    # LI=0, VN=4, Mode=4 (server)
    # Stratum=1, Poll/Precision basic
    # Originate Timestamp = client's Transmit Timestamp (bytes 40..47 of request)
    # Receive/Transmit = now
    if len(req) < 48:
        req = req.ljust(48, b"\x00")

    li_vn_mode = (0 << 6) | (4 << 3) | 4
    stratum = 1
    poll = 4
    precision = -20 & 0xFF

    root_delay = 0
    root_disp = 0
    ref_id = b"LOCL"  # local clock

    now = time.time()
    ref_sec, ref_frac = unix_to_ntp_ts(now)
    recv_sec, recv_frac = unix_to_ntp_ts(now)
    tx_sec, tx_frac = unix_to_ntp_ts(now)

    # Client's transmit timestamp becomes originate timestamp
    orig = req[40:48]  # 8 bytes (sec, frac)
    orig_sec, orig_frac = struct.unpack("!II", orig)

    # Reference timestamp: use now
    packet = struct.pack(
        "!BBBBIII4sIIIIIIII",
        li_vn_mode, stratum, poll, precision,
        root_delay, root_disp, 0, ref_id,
        ref_sec, ref_frac,
        orig_sec, orig_frac,
        recv_sec, recv_frac,
        tx_sec, tx_frac
    )
    return packet[:48]

async def main():
    c = SwitchyardClient(client_name="svc_ntp")
    await c.connect()

    ep = await c.create_endpoint(NTP_ENDPOINT_NAME)
    await c.subscribe(ep.endpoint_id)

    print(f"[svc_ntp] endpoint_id={ep.endpoint_id} mac={ep.mac} ip={NTP_IP} udp_port={NTP_PORT}")

    async for (_dst_ep_id, frame) in c.recv_frames():
        try:
            eth = parse_eth(frame)

            # ARP
            if eth.ethertype == ETH_TYPE_ARP:
                arp = parse_arp(eth.payload)
                if arp.op == ARP_OP_REQUEST and arp.tpa == NTP_IP:
                    arp_rep = build_arp_reply(
                        src_mac=ep.mac, src_ip=NTP_IP,
                        dst_mac=arp.sha, dst_ip=arp.spa
                    )
                    rep_frame = build_eth(dst_mac=arp.sha, src_mac=ep.mac, ethertype=ETH_TYPE_ARP, payload=arp_rep)
                    await c.send_frame(ep.endpoint_id, rep_frame)
                continue

            # IPv4/UDP
            if eth.ethertype != ETH_TYPE_IPV4:
                continue
            ip = parse_ipv4(eth.payload)
            if ip.proto != IPPROTO_UDP:
                continue

            udp = parse_udp(ip.payload)
            if udp.dst_port != NTP_PORT:
                continue

            resp_ntp = build_ntp_response(udp.payload)
            resp_udp = build_udp(src_ip=NTP_IP, dst_ip=ip.src_ip, src_port=NTP_PORT, dst_port=udp.src_port, payload=resp_ntp)
            resp_ip  = build_ipv4(src_ip=NTP_IP, dst_ip=ip.src_ip, proto=IPPROTO_UDP, payload=resp_udp)
            resp_eth = build_eth(dst_mac=eth.src_mac, src_mac=ep.mac, ethertype=ETH_TYPE_IPV4, payload=resp_ip)

            await c.send_frame(ep.endpoint_id, resp_eth)

        except Exception:
            continue

if __name__ == "__main__":
    asyncio.run(main())