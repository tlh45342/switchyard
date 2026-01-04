# switchyard.py
from __future__ import annotations

import asyncio
import json
import struct
import ipaddress
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple, AsyncIterator

# -----------------------------
# Switchyard Protocol v1
# -----------------------------
SY_VERSION = 1

# Message types
HELLO            = 1
WELCOME          = 2

ENDPOINT_CREATE  = 10
ENDPOINT_CREATED = 11
ENDPOINT_LOOKUP  = 12
ENDPOINT_INFO    = 13

SUBSCRIBE        = 20
SUBSCRIBED       = 21

PACKET_OUT       = 30
PACKET_IN        = 31

ERROR            = 100

# Flags
FLAG_PROMISC     = 0x00000001

# Framing:
#   u32 msg_len (bytes after this u32; i.e., header+payload)
#   u16 version
#   u16 type
#   u32 endpoint_id
#   u32 flags
#   payload (msg_len - 12 bytes)
_HDR_NO_LEN = struct.Struct("!HHII")  # ver,type,ep,flags
_HDR_SIZE_NO_LEN = _HDR_NO_LEN.size   # 12


# -----------------------------
# Utilities
# -----------------------------
def mac_to_bytes(mac: str) -> bytes:
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"bad mac: {mac}")
    return bytes(int(p, 16) for p in parts)

def mac_from_bytes(b: bytes) -> str:
    if len(b) != 6:
        raise ValueError("mac bytes must be len 6")
    return ":".join(f"{x:02x}" for x in b)

def is_broadcast_mac(b: bytes) -> bool:
    return b == b"\xff\xff\xff\xff\xff\xff"

def ipv4_to_bytes(ip: str) -> bytes:
    return ipaddress.IPv4Address(ip).packed

def ipv4_from_bytes(b: bytes) -> str:
    return str(ipaddress.IPv4Address(b))

def checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


# -----------------------------
# Packet primitives
# Ethernet + ARP + IPv4 + UDP
# -----------------------------
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_ARP  = 0x0806

IPPROTO_UDP = 17

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC      = "00:00:00:00:00:00"

@dataclass
class EthFrame:
    dst_mac: str
    src_mac: str
    ethertype: int
    payload: bytes

def parse_eth(frame: bytes) -> EthFrame:
    if len(frame) < 14:
        raise ValueError("frame too short for ethernet")
    dst = frame[0:6]
    src = frame[6:12]
    et = struct.unpack("!H", frame[12:14])[0]
    return EthFrame(mac_from_bytes(dst), mac_from_bytes(src), et, frame[14:])

def build_eth(dst_mac: str, src_mac: str, ethertype: int, payload: bytes) -> bytes:
    return mac_to_bytes(dst_mac) + mac_to_bytes(src_mac) + struct.pack("!H", ethertype) + payload

# ---- ARP (Ethernet/IPv4 ARP) ----
ARP_HTYPE_ETH = 1
ARP_PTYPE_IPV4 = 0x0800
ARP_HLEN_ETH = 6
ARP_PLEN_IPV4 = 4
ARP_OP_REQUEST = 1
ARP_OP_REPLY   = 2

@dataclass
class ArpPacket:
    op: int
    sha: str
    spa: str
    tha: str
    tpa: str

def parse_arp(pkt: bytes) -> ArpPacket:
    # RFC 826: htype(2) ptype(2) hlen(1) plen(1) oper(2) sha(6) spa(4) tha(6) tpa(4)
    if len(pkt) < 28:
        raise ValueError("arp too short")
    htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", pkt[:8])
    if htype != ARP_HTYPE_ETH or ptype != ARP_PTYPE_IPV4 or hlen != ARP_HLEN_ETH or plen != ARP_PLEN_IPV4:
        raise ValueError("unsupported arp format")
    sha = mac_from_bytes(pkt[8:14])
    spa = ipv4_from_bytes(pkt[14:18])
    tha = mac_from_bytes(pkt[18:24])
    tpa = ipv4_from_bytes(pkt[24:28])
    return ArpPacket(op=oper, sha=sha, spa=spa, tha=tha, tpa=tpa)

def build_arp(op: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    hdr = struct.pack("!HHBBH", ARP_HTYPE_ETH, ARP_PTYPE_IPV4, ARP_HLEN_ETH, ARP_PLEN_IPV4, op)
    return hdr + mac_to_bytes(sha) + ipv4_to_bytes(spa) + mac_to_bytes(tha) + ipv4_to_bytes(tpa)

def build_arp_request(src_mac: str, src_ip: str, target_ip: str) -> bytes:
    return build_arp(ARP_OP_REQUEST, sha=src_mac, spa=src_ip, tha=ZERO_MAC, tpa=target_ip)

def build_arp_reply(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> bytes:
    return build_arp(ARP_OP_REPLY, sha=src_mac, spa=src_ip, tha=dst_mac, tpa=dst_ip)

# ---- IPv4 ----
@dataclass
class IPv4Packet:
    src_ip: str
    dst_ip: str
    proto: int
    payload: bytes
    ttl: int = 64
    ident: int = 0

def parse_ipv4(pkt: bytes) -> IPv4Packet:
    if len(pkt) < 20:
        raise ValueError("ipv4 too short")
    vihl = pkt[0]
    ver = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    if ver != 4 or ihl < 20 or len(pkt) < ihl:
        raise ValueError("bad ipv4 header")
    total_len = struct.unpack("!H", pkt[2:4])[0]
    if total_len > len(pkt):
        raise ValueError("ipv4 total_len beyond buffer")
    proto = pkt[9]
    src = ipv4_from_bytes(pkt[12:16])
    dst = ipv4_from_bytes(pkt[16:20])
    return IPv4Packet(src, dst, proto, pkt[ihl:total_len], ttl=pkt[8], ident=struct.unpack("!H", pkt[4:6])[0])

def build_ipv4(src_ip: str, dst_ip: str, proto: int, payload: bytes, ttl: int = 64, ident: int = 0) -> bytes:
    ihl = 5
    ver = 4
    vihl = (ver << 4) | ihl
    tos = 0
    total_len = 20 + len(payload)
    flags_frag = 0
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        vihl, tos, total_len, ident, flags_frag, ttl, proto, 0,
        ipv4_to_bytes(src_ip), ipv4_to_bytes(dst_ip)
    )
    csum = checksum16(hdr)
    hdr = hdr[:10] + struct.pack("!H", csum) + hdr[12:]
    return hdr + payload

# ---- UDP ----
@dataclass
class UDPSegment:
    src_port: int
    dst_port: int
    payload: bytes

def parse_udp(seg: bytes) -> UDPSegment:
    if len(seg) < 8:
        raise ValueError("udp too short")
    srcp, dstp, length, csum = struct.unpack("!HHHH", seg[:8])
    if length < 8 or length > len(seg):
        raise ValueError("udp length invalid")
    return UDPSegment(srcp, dstp, seg[8:length])

def build_udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = ipv4_to_bytes(src_ip) + ipv4_to_bytes(dst_ip) + struct.pack("!BBH", 0, IPPROTO_UDP, length)
    csum = checksum16(pseudo + hdr + payload)
    hdr = struct.pack("!HHHH", src_port, dst_port, length, csum)
    return hdr + payload


# -----------------------------
# Switchyard Client SDK (single-reader pump)
# -----------------------------
@dataclass
class Endpoint:
    endpoint_id: int
    name: str
    mac: str

class SwitchyardClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 9999, client_name: str = "pyclient"):
        self.host = host
        self.port = port
        self.client_name = client_name

        self._r: Optional[asyncio.StreamReader] = None
        self._w: Optional[asyncio.StreamWriter] = None

        # PACKET_IN frames land here
        self._recv_q: "asyncio.Queue[Tuple[int,int,bytes]]" = asyncio.Queue()

        # All control-plane replies land here
        self._ctrl_q: "asyncio.Queue[Tuple[int,int,int,bytes]]" = asyncio.Queue()

        self._pump_task: Optional[asyncio.Task] = None

    async def connect(self) -> None:
        self._r, self._w = await asyncio.open_connection(self.host, self.port)
        self._pump_task = asyncio.create_task(self._pump())

        await self._send_json(HELLO, 0, 0, {"client_name": self.client_name})
        mtype, ep, flags, payload = await self._recv_ctrl()
        if mtype != WELCOME:
            raise RuntimeError(f"expected WELCOME, got {mtype}, payload={payload!r}")

    async def close(self) -> None:
        if self._pump_task:
            self._pump_task.cancel()
            self._pump_task = None
        if self._w:
            self._w.close()
            await self._w.wait_closed()

    async def create_endpoint(self, name: str, mac: Optional[str] = None) -> Endpoint:
        req: Dict[str, Any] = {"name": name}
        if mac:
            req["mac"] = mac
        await self._send_json(ENDPOINT_CREATE, 0, 0, req)

        mtype, ep, flags, payload = await self._recv_ctrl()
        if mtype == ERROR:
            raise RuntimeError(payload.decode("utf-8", "replace"))
        if mtype != ENDPOINT_CREATED:
            raise RuntimeError(f"expected ENDPOINT_CREATED, got {mtype}, payload={payload!r}")

        obj = json.loads(payload.decode("utf-8"))
        return Endpoint(endpoint_id=obj["endpoint_id"], name=obj["name"], mac=obj["mac"])

    async def lookup_endpoint(self, name: str) -> Endpoint:
        await self._send_json(ENDPOINT_LOOKUP, 0, 0, {"name": name})

        mtype, ep, flags, payload = await self._recv_ctrl()
        if mtype == ERROR:
            raise RuntimeError(payload.decode("utf-8", "replace"))
        if mtype != ENDPOINT_INFO:
            raise RuntimeError(f"expected ENDPOINT_INFO, got {mtype}, payload={payload!r}")

        obj = json.loads(payload.decode("utf-8"))
        return Endpoint(endpoint_id=obj["endpoint_id"], name=obj["name"], mac=obj["mac"])

    async def subscribe(self, endpoint_id: int, promisc: bool = False) -> None:
        flags = FLAG_PROMISC if promisc else 0
        await self._send_json(SUBSCRIBE, endpoint_id, flags, {"endpoint_id": endpoint_id, "promisc": promisc})

        mtype, ep, rflags, payload = await self._recv_ctrl()
        if mtype == ERROR:
            raise RuntimeError(payload.decode("utf-8", "replace"))
        if mtype != SUBSCRIBED:
            raise RuntimeError(f"expected SUBSCRIBED, got {mtype}, payload={payload!r}")

    async def send_frame(self, endpoint_id: int, frame: bytes) -> None:
        await self._send_raw(PACKET_OUT, endpoint_id, 0, frame)

    async def recv_frames(self) -> AsyncIterator[Tuple[int, bytes]]:
        while True:
            ep, flags, frame = await self._recv_q.get()
            yield (ep, frame)

    # ---- internal ----
    async def _pump(self) -> None:
        assert self._r is not None
        while True:
            mtype, ep, flags, payload = await self._recv_one()
            if mtype == PACKET_IN:
                self._recv_q.put_nowait((ep, flags, payload))
            else:
                self._ctrl_q.put_nowait((mtype, ep, flags, payload))

    async def _recv_ctrl(self) -> Tuple[int, int, int, bytes]:
        return await self._ctrl_q.get()

    async def _send_json(self, mtype: int, endpoint_id: int, flags: int, obj: Dict[str, Any]) -> None:
        data = json.dumps(obj).encode("utf-8")
        await self._send_raw(mtype, endpoint_id, flags, data)

    async def _send_raw(self, mtype: int, endpoint_id: int, flags: int, payload: bytes) -> None:
        assert self._w is not None
        header = _HDR_NO_LEN.pack(SY_VERSION, mtype, endpoint_id, flags)
        msg_len = len(header) + len(payload)
        self._w.write(struct.pack("!I", msg_len) + header + payload)
        await self._w.drain()

    async def _recv_one(self) -> Tuple[int, int, int, bytes]:
        assert self._r is not None
        raw_len = await self._r.readexactly(4)
        (msg_len,) = struct.unpack("!I", raw_len)
        blob = await self._r.readexactly(msg_len)
        ver, mtype, ep, flags = _HDR_NO_LEN.unpack(blob[:_HDR_SIZE_NO_LEN])
        if ver != SY_VERSION:
            raise RuntimeError(f"protocol version mismatch: {ver} != {SY_VERSION}")
        payload = blob[_HDR_SIZE_NO_LEN:]
        return (mtype, ep, flags, payload)
