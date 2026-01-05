# cli_ntp.py

# Copyright 2025 Thomas L Hamilton
# 
# Licensed under the Apache License, Version 2.0 (the "License"); 
# you may not use this file except in compliance with the License. 
# You may obtain a copy of the License at 
# 
#     http://www.apache.org/licenses/LICENSE-2.0

from __future__ import annotations

import asyncio
import struct
import time

from switchyard import (
    SwitchyardClient,
    parse_eth, parse_ipv4, parse_udp, parse_arp,
    build_udp, build_ipv4, build_eth,
    build_arp_request,
    ETH_TYPE_ARP, ETH_TYPE_IPV4, IPPROTO_UDP,
    ARP_OP_REPLY,
    BROADCAST_MAC,
)

CLIENT_ENDPOINT_NAME = "cli_ntp"
CLIENT_IP = "10.0.0.10"
CLIENT_PORT = 40000

NTP_IP = "10.0.0.3"
NTP_PORT = 123
NTP_EPOCH_DELTA = 2208988800

async def arp_resolve(c: SwitchyardClient, ep_id: int, mac: str, ip: str, target_ip: str, timeout_s: float = 2.0) -> str:
    arp_req = build_arp_request(src_mac=mac, src_ip=ip, target_ip=target_ip)
    frame = build_eth(dst_mac=BROADCAST_MAC, src_mac=mac, ethertype=ETH_TYPE_ARP, payload=arp_req)
    await c.send_frame(ep_id, frame)

    async def waiter():
        async for (_dst_ep_id, fr) in c.recv_frames():
            try:
                e = parse_eth(fr)
                if e.ethertype != ETH_TYPE_ARP:
                    continue
                a = parse_arp(e.payload)
                if a.op == ARP_OP_REPLY and a.spa == target_ip and a.tpa == ip:
                    return a.sha
            except Exception:
                continue

    return await asyncio.wait_for(waiter(), timeout=timeout_s)

def unix_to_ntp(t: float) -> tuple[int, int]:
    sec = int(t) + NTP_EPOCH_DELTA
    frac = int((t - int(t)) * (1 << 32)) & 0xFFFFFFFF
    return sec & 0xFFFFFFFF, frac

def ntp_to_unix(sec: int, frac: int) -> float:
    return (sec - NTP_EPOCH_DELTA) + (frac / float(1 << 32))

def build_ntp_request() -> bytes:
    # LI=0, VN=4, Mode=3 (client)
    li_vn_mode = (0 << 6) | (4 << 3) | 3
    pkt = bytearray(48)
    pkt[0] = li_vn_mode
    # Put client's transmit timestamp at bytes 40..47
    now = time.time()
    sec, frac = unix_to_ntp(now)
    pkt[40:48] = struct.pack("!II", sec, frac)
    return bytes(pkt)

async def main():
    c = SwitchyardClient(client_name="cli_ntp")
    await c.connect()

    ep = await c.create_endpoint(CLIENT_ENDPOINT_NAME)
    await c.subscribe(ep.endpoint_id)

    dst_mac = await arp_resolve(c, ep.endpoint_id, ep.mac, CLIENT_IP, NTP_IP, timeout_s=3.0)
    print(f"[cli_ntp] ARP resolved {NTP_IP} -> {dst_mac}")

    req = build_ntp_request()
    udp = build_udp(src_ip=CLIENT_IP, dst_ip=NTP_IP, src_port=CLIENT_PORT, dst_port=NTP_PORT, payload=req)
    ip  = build_ipv4(src_ip=CLIENT_IP, dst_ip=NTP_IP, proto=IPPROTO_UDP, payload=udp)
    eth = build_eth(dst_mac=dst_mac, src_mac=ep.mac, ethertype=ETH_TYPE_IPV4, payload=ip)

    await c.send_frame(ep.endpoint_id, eth)
    print("[cli_ntp] sent NTP request")

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

            if len(u2.payload) < 48:
                print("[cli_ntp] short reply")
                break

            tx_sec, tx_frac = struct.unpack("!II", u2.payload[40:48])
            t = ntp_to_unix(tx_sec, tx_frac)
            print(f"[cli_ntp] server transmit time: {t:.6f} (unix)")
            break
        except Exception:
            continue

    await c.close()

if __name__ == "__main__":
    asyncio.run(main())
