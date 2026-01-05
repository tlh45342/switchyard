# switchyardd.py

# Copyright 2025 Thomas L Hamilton
# 
# Licensed under the Apache License, Version 2.0 (the "License"); 
# you may not use this file except in compliance with the License. 
# You may obtain a copy of the License at 
# 
#     http://www.apache.org/licenses/LICENSE-2.0

from __future__ import annotations

import asyncio
import json
import struct
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple, Any

from switchyard import (
    SY_VERSION, _HDR_NO_LEN, _HDR_SIZE_NO_LEN,
    HELLO, WELCOME,
    ENDPOINT_CREATE, ENDPOINT_CREATED, ENDPOINT_LOOKUP, ENDPOINT_INFO,
    SUBSCRIBE, SUBSCRIBED,
    PACKET_OUT, PACKET_IN,
    ERROR, FLAG_PROMISC,
    parse_eth, mac_from_bytes, mac_to_bytes, is_broadcast_mac
)

# Switchyard locally-administered MAC prefix: 02:53:59:xx:xx:xx
SY_MAC_PREFIX = bytes([0x02, 0x53, 0x59])

def alloc_mac(counter: int) -> str:
    # last 3 bytes from counter
    b = SY_MAC_PREFIX + bytes([(counter >> 16) & 0xFF, (counter >> 8) & 0xFF, counter & 0xFF])
    return mac_from_bytes(b)

def pack_msg(mtype: int, endpoint_id: int, flags: int, payload: bytes) -> bytes:
    header = _HDR_NO_LEN.pack(SY_VERSION, mtype, endpoint_id, flags)
    msg_len = len(header) + len(payload)
    return struct.pack("!I", msg_len) + header + payload

def pack_json(mtype: int, endpoint_id: int, flags: int, obj: Any) -> bytes:
    return pack_msg(mtype, endpoint_id, flags, json.dumps(obj).encode("utf-8"))

@dataclass
class Subscriber:
    writer: asyncio.StreamWriter
    flags: int = 0  # PROMISC, etc.

@dataclass
class Endpoint:
    endpoint_id: int
    name: str
    mac: str
    owner: asyncio.StreamWriter
    subscribers: List[Subscriber] = field(default_factory=list)

class SwitchyardDaemon:
    def __init__(self):
        self._next_ep_id = 1
        self._mac_counter = 1

        self.endpoints_by_id: Dict[int, Endpoint] = {}
        self.endpoints_by_name: Dict[str, Endpoint] = {}
        self.endpoints_by_mac: Dict[bytes, Endpoint] = {}  # 6 bytes

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        try:
            # Expect HELLO
            mtype, ep, flags, payload = await self._recv_one(reader)
            if mtype != HELLO:
                await self._send_error(writer, f"expected HELLO, got {mtype}")
                writer.close()
                await writer.wait_closed()
                return

            await self._send_raw(writer, WELCOME, 0, 0, json.dumps({"server": "switchyardd", "version": SY_VERSION}).encode("utf-8"))

            while True:
                mtype, ep, flags, payload = await self._recv_one(reader)
                if mtype == ENDPOINT_CREATE:
                    await self._handle_endpoint_create(writer, payload)
                elif mtype == ENDPOINT_LOOKUP:
                    await self._handle_endpoint_lookup(writer, payload)
                elif mtype == SUBSCRIBE:
                    await self._handle_subscribe(writer, ep, flags, payload)
                elif mtype == PACKET_OUT:
                    await self._handle_packet_out(writer, ep, payload)
                else:
                    await self._send_error(writer, f"unknown message type: {mtype}")
        except asyncio.IncompleteReadError:
            pass
        except ConnectionResetError:
            pass
        finally:
            # cleanup: remove subscribers belonging to this writer
            self._remove_writer_from_subscribers(writer)
            # NOTE: endpoints remain (you might choose to auto-delete owned endpoints)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_endpoint_create(self, writer: asyncio.StreamWriter, payload: bytes):
        try:
            obj = json.loads(payload.decode("utf-8"))
            name = str(obj["name"])
            mac = obj.get("mac")
            if mac is None:
                mac = alloc_mac(self._mac_counter)
                self._mac_counter += 1
        except Exception as e:
            await self._send_error(writer, f"bad ENDPOINT_CREATE: {e}")
            return

        if name in self.endpoints_by_name:
            await self._send_error(writer, f"endpoint name already exists: {name}")
            return

        mac_b = mac_to_bytes(mac)
        if mac_b in self.endpoints_by_mac:
            await self._send_error(writer, f"endpoint mac already exists: {mac}")
            return

        ep_id = self._next_ep_id
        self._next_ep_id += 1

        ep = Endpoint(endpoint_id=ep_id, name=name, mac=mac, owner=writer)
        self.endpoints_by_id[ep_id] = ep
        self.endpoints_by_name[name] = ep
        self.endpoints_by_mac[mac_b] = ep

        await self._send_raw(writer, ENDPOINT_CREATED, 0, 0, json.dumps({"endpoint_id": ep_id, "name": name, "mac": mac}).encode("utf-8"))

    async def _handle_endpoint_lookup(self, writer: asyncio.StreamWriter, payload: bytes):
        try:
            obj = json.loads(payload.decode("utf-8"))
            name = str(obj["name"])
        except Exception as e:
            await self._send_error(writer, f"bad ENDPOINT_LOOKUP: {e}")
            return

        ep = self.endpoints_by_name.get(name)
        if not ep:
            await self._send_error(writer, f"no such endpoint: {name}")
            return

        await self._send_raw(writer, ENDPOINT_INFO, 0, 0, json.dumps({"endpoint_id": ep.endpoint_id, "name": ep.name, "mac": ep.mac}).encode("utf-8"))

    async def _handle_subscribe(self, writer: asyncio.StreamWriter, endpoint_id: int, flags: int, payload: bytes):
        ep = self.endpoints_by_id.get(endpoint_id)
        if not ep:
            await self._send_error(writer, f"subscribe: unknown endpoint_id {endpoint_id}")
            return

        # allow multiple subscribers per endpoint (tools, sniffers, etc.)
        ep.subscribers.append(Subscriber(writer=writer, flags=flags))
        await self._send_raw(writer, SUBSCRIBED, endpoint_id, flags, b"{}")

    async def _handle_packet_out(self, writer: asyncio.StreamWriter, src_endpoint_id: int, frame: bytes):
        src_ep = self.endpoints_by_id.get(src_endpoint_id)
        if not src_ep:
            await self._send_error(writer, f"PACKET_OUT: unknown src endpoint_id {src_endpoint_id}")
            return

        # Route by destination MAC (Ethernet)
        try:
            eth = parse_eth(frame)
            dst_b = mac_to_bytes(eth.dst_mac)
            src_b = mac_to_bytes(eth.src_mac)
        except Exception as e:
            await self._send_error(writer, f"PACKET_OUT: bad ethernet frame: {e}")
            return

        # Keep mac table in sync for source MAC
        self.endpoints_by_mac[src_b] = src_ep

        if is_broadcast_mac(dst_b):
            await self._flood(src_endpoint_id, frame)
            return

        dst_ep = self.endpoints_by_mac.get(dst_b)
        if dst_ep is None:
            # Unknown unicast => flood (like a switch)
            await self._flood(src_endpoint_id, frame)
            return

        await self._deliver(dst_ep, frame)

    async def _deliver(self, dst_ep: Endpoint, frame: bytes):
        # Deliver to all subscribers of dst_ep, and to PROMISC subscribers on other endpoints? (not in v1)
        dead: List[Subscriber] = []
        for sub in dst_ep.subscribers:
            try:
                sub.writer.write(pack_msg(PACKET_IN, dst_ep.endpoint_id, sub.flags, frame))
                await sub.writer.drain()
            except Exception:
                dead.append(sub)
        if dead:
            dst_ep.subscribers = [s for s in dst_ep.subscribers if s not in dead]

    async def _flood(self, src_endpoint_id: int, frame: bytes):
        # Flood to all endpoints except the source endpoint.
        for ep_id, ep in self.endpoints_by_id.items():
            if ep_id == src_endpoint_id:
                continue
            await self._deliver(ep, frame)

    def _remove_writer_from_subscribers(self, writer: asyncio.StreamWriter):
        for ep in self.endpoints_by_id.values():
            ep.subscribers = [s for s in ep.subscribers if s.writer is not writer]

    async def _send_error(self, writer: asyncio.StreamWriter, msg: str):
        writer.write(pack_json(ERROR, 0, 0, {"error": msg}))
        await writer.drain()

    async def _send_raw(self, writer: asyncio.StreamWriter, mtype: int, endpoint_id: int, flags: int, payload: bytes):
        writer.write(pack_msg(mtype, endpoint_id, flags, payload))
        await writer.drain()

    async def _recv_one(self, reader: asyncio.StreamReader) -> Tuple[int, int, int, bytes]:
        raw_len = await reader.readexactly(4)
        (msg_len,) = struct.unpack("!I", raw_len)
        blob = await reader.readexactly(msg_len)
        ver, mtype, ep, flags = _HDR_NO_LEN.unpack(blob[:_HDR_SIZE_NO_LEN])
        if ver != SY_VERSION:
            raise RuntimeError(f"protocol version mismatch: {ver} != {SY_VERSION}")
        payload = blob[_HDR_SIZE_NO_LEN:]
        return (mtype, ep, flags, payload)

async def main(host: str = "127.0.0.1", port: int = 9999):
    daemon = SwitchyardDaemon()
    server = await asyncio.start_server(daemon.handle_client, host, port)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"[switchyardd] listening on {addrs}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
