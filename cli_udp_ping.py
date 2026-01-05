# cli_udp_ping.py

# Copyright 2025 Thomas L Hamilton
# 
# Licensed under the Apache License, Version 2.0 (the "License"); 
# you may not use this file except in compliance with the License. 
# You may obtain a copy of the License at 
# 
#     http://www.apache.org/licenses/LICENSE-2.0

from __future__ import annotations

import asyncio
import os
from switchyard import (
    SwitchyardClient,
    parse_eth, parse_ipv4, parse_udp, parse_arp,
    build_udp, build_ipv4, build_eth,
    build_arp_request,
    ETH_TYPE_IPV4, ETH_TYPE_ARP, IPPROTO_UDP,
    ARP_OP_REPLY,
    BROADCAST_MAC,
)

CLIENT_ENDPOINT_NAME = "cli1"
CLIENT_IP = "10.0.0.1"
CLIENT_PORT = 12345

ECHO_NAME = "svc_echo"
ECHO_IP = "10.0.0.2"
ECHO_PORT = 7007

async def arp_resolve(c: SwitchyardClient, cli_ep_id: int, cli_mac: str, cli_ip: str, target_ip: str, timeout_s: float = 2.0) -> str:
    # Broadcast ARP request
    arp_req = build_arp_request(src_mac=cli_mac, src_ip=cli_ip, target_ip=target_ip)
    frame = build_eth(dst_mac=BROADCAST_MAC, src_mac=cli_mac, ethertype=ETH_TYPE_ARP, payload=arp_req)
    await c.send_frame(cli_ep_id, frame)

    # Wait for ARP reply
    async def waiter():
        async for (_dst_ep_id, fr) in c.recv_frames():
            try:
                e = parse_eth(fr)
                if e.ethertype != ETH_TYPE_ARP:
                    continue
                a = parse_arp(e.payload)
                if a.op != ARP_OP_REPLY:
                    continue
                # Expect: spa == target_ip, tpa == cli_ip
                if a.spa == target_ip and a.tpa == cli_ip:
                    return a.sha
            except Exception:
                continue

    return await asyncio.wait_for(waiter(), timeout=timeout_s)

async def main():
    c = SwitchyardClient(client_name="cli_udp_ping")
    await c.connect()

    cli_ep = await c.create_endpoint(CLIENT_ENDPOINT_NAME)
    await c.subscribe(cli_ep.endpoint_id)

    # Ensure service exists (name lookup still useful for “is it running”)
    echo_ep = await c.lookup_endpoint(ECHO_NAME)
    print(f"[cli] my endpoint_id={cli_ep.endpoint_id} mac={cli_ep.mac} ip={CLIENT_IP}")
    print(f"[cli] echo endpoint_id={echo_ep.endpoint_id} (name lookup only) ip={ECHO_IP}:{ECHO_PORT}")

    # ARP for the echo server's IP
    dst_mac = await arp_resolve(c, cli_ep.endpoint_id, cli_ep.mac, CLIENT_IP, ECHO_IP, timeout_s=3.0)
    print(f"[cli] ARP resolved {ECHO_IP} -> {dst_mac}")

    msg = os.environ.get("PING_MSG", "marco polo").encode("utf-8")

    udp = build_udp(src_ip=CLIENT_IP, dst_ip=ECHO_IP, src_port=CLIENT_PORT, dst_port=ECHO_PORT, payload=msg)
    ip = build_ipv4(src_ip=CLIENT_IP, dst_ip=ECHO_IP, proto=IPPROTO_UDP, payload=udp)
    eth = build_eth(dst_mac=dst_mac, src_mac=cli_ep.mac, ethertype=ETH_TYPE_IPV4, payload=ip)

    await c.send_frame(cli_ep.endpoint_id, eth)
    print(f"[cli] sent {len(msg)} bytes: {msg!r}")

    # Wait for one UDP response
    async for (_dst_ep_id, frame) in c.recv_frames():
        try:
            e = parse_eth(frame)
            if e.ethertype != ETH_TYPE_IPV4:
                continue
            ip2 = parse_ipv4(e.payload)
            if ip2.proto != IPPROTO_UDP:
                continue
            u2 = parse_udp(ip2.payload)
            if u2.dst_port != CLIENT_PORT:
                continue
            print(f"[cli] got reply from {ip2.src_ip}:{u2.src_port}: {u2.payload!r}")
            break
        except Exception:
            continue

    await c.close()

if __name__ == "__main__":
    asyncio.run(main())
