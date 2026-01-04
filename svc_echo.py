# svc_echo.py
from __future__ import annotations

import asyncio
from switchyard import (
    SwitchyardClient,
    parse_eth, parse_ipv4, parse_udp, parse_arp,
    build_udp, build_ipv4, build_eth,
    build_arp_reply, build_arp_request,
    ETH_TYPE_IPV4, ETH_TYPE_ARP, IPPROTO_UDP,
    ARP_OP_REQUEST,
)

ECHO_ENDPOINT_NAME = "svc_echo"
ECHO_IP = "10.0.0.2"
ECHO_PORT = 7007

async def main():
    c = SwitchyardClient(client_name="svc_echo")
    await c.connect()

    ep = await c.create_endpoint(ECHO_ENDPOINT_NAME)
    await c.subscribe(ep.endpoint_id)

    print(f"[svc_echo] endpoint_id={ep.endpoint_id} mac={ep.mac} ip={ECHO_IP} udp_port={ECHO_PORT}")

    async for (dst_ep_id, frame) in c.recv_frames():
        try:
            eth = parse_eth(frame)

            # ---- ARP ----
            if eth.ethertype == ETH_TYPE_ARP:
                arp = parse_arp(eth.payload)
                if arp.op == ARP_OP_REQUEST and arp.tpa == ECHO_IP:
                    # Reply: "ECHO_IP is at ep.mac"
                    arp_rep = build_arp_reply(
                        src_mac=ep.mac, src_ip=ECHO_IP,
                        dst_mac=arp.sha, dst_ip=arp.spa
                    )
                    rep_frame = build_eth(
                        dst_mac=arp.sha,
                        src_mac=ep.mac,
                        ethertype=ETH_TYPE_ARP,
                        payload=arp_rep
                    )
                    await c.send_frame(ep.endpoint_id, rep_frame)
                continue

            # ---- UDP Echo ----
            if eth.ethertype != ETH_TYPE_IPV4:
                continue

            ip = parse_ipv4(eth.payload)
            if ip.proto != IPPROTO_UDP:
                continue

            udp = parse_udp(ip.payload)
            if udp.dst_port != ECHO_PORT:
                continue

            # Build response: swap MAC, swap IP, swap ports, echo payload
            resp_udp = build_udp(
                src_ip=ECHO_IP,
                dst_ip=ip.src_ip,
                src_port=ECHO_PORT,
                dst_port=udp.src_port,
                payload=udp.payload
            )
            resp_ip = build_ipv4(
                src_ip=ECHO_IP,
                dst_ip=ip.src_ip,
                proto=IPPROTO_UDP,
                payload=resp_udp
            )
            resp_eth = build_eth(
                dst_mac=eth.src_mac,
                src_mac=ep.mac,
                ethertype=ETH_TYPE_IPV4,
                payload=resp_ip
            )
            await c.send_frame(ep.endpoint_id, resp_eth)

        except Exception:
            continue

if __name__ == "__main__":
    asyncio.run(main())
