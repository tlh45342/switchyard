# Switchyard

**Switchyard** is a tiny, deterministic “virtual network” fabric for development/testing.  
It routes **raw Ethernet frames** between user-space endpoints over a simple **localhost TCP** protocol.

Right now it ships with:
- a fabric daemon (`switchyardd.py`)
- a Python client SDK (`switchyard.py`)
- a UDP echo service (`svc_echo.py`)
- a UDP “ping” client (`cli_udp_ping.py`)

This is a foundation for building DHCP/DNS/ARP/NTP-style services in a controlled, inspectable environment before you ever touch real NICs/TAP/Npcap.

---

## Why Switchyard exists

When you’re building a VM/emulator networking device, you want:
- repeatable behavior (no “real network” chaos)
- easy packet capture/analysis
- a clear boundary between “VM world” and “host world”
- a place to inject faults (drops/latency/reorder) later

Switchyard provides that boundary.

---

## Quick start

### Requirements
- Python 3.10+ (tested on Windows with Python 3.12)
- No third-party dependencies

### Run (3 terminals)

**Terminal 1 (fabric daemon):**
```bash
python switchyardd.py
Terminal 2 (UDP echo service):

bash
Copy code
python svc_echo.py
Terminal 3 (client ping):

bash
Copy code
python cli_udp_ping.py
Expected output (client):

csharp
Copy code
[cli] sent ... b'marco polo'
[cli] got reply ... b'marco polo'
Project layout
graphql
Copy code
switchyard/
  switchyard.py      # SDK + protocol + packet primitives (Eth/IPv4/UDP)
  switchyardd.py     # fabric daemon (MAC learning + flood on unknown/broadcast)
  svc_echo.py        # UDP echo service (listens on UDP port 7007)
  cli_udp_ping.py    # client that sends one UDP datagram and waits for echo
How it works
Transport / Control plane / Data plane
All processes connect to the fabric daemon via TCP loopback (default 127.0.0.1:9999).

Messages are length-prefixed.

Control messages carry UTF-8 JSON.

Packet messages carry raw Ethernet frame bytes.

Packet unit
The fabric moves Ethernet frames (L2) as opaque bytes.
This keeps ARP/DHCP/DNS feasible later (they fundamentally depend on L2/L3).

Switching behavior (v1)
Learns source MAC → endpoint mapping

For unicast:

if destination MAC is known: deliver to that endpoint

otherwise: flood (like a switch)

Broadcast MAC (ff:ff:ff:ff:ff:ff) floods

Locally administered MACs
Switchyard uses a locally administered MAC prefix:

02:53:59:xx:xx:xx (the 02 indicates a locally administered, unicast MAC)

Example:

02:53:59:00:00:01

02:53:59:00:00:02

This avoids using real vendor OUIs.

Switchyard Protocol v1 (wire format)
Each message on the TCP stream:

u32 msg_len (network order) — number of bytes after this field

u16 version

u16 type

u32 endpoint_id

u32 flags

payload (msg_len - 12 bytes)

Payload:

Control plane: UTF-8 JSON bytes

Data plane:

PACKET_OUT: raw Ethernet frame bytes (client → fabric)

PACKET_IN: raw Ethernet frame bytes (fabric → subscriber)

Message types (current):

HELLO, WELCOME

ENDPOINT_CREATE, ENDPOINT_CREATED

ENDPOINT_LOOKUP, ENDPOINT_INFO

SUBSCRIBE, SUBSCRIBED

PACKET_OUT, PACKET_IN

ERROR

Demo services
UDP Echo service
svc_echo.py subscribes to its endpoint and:

accepts IPv4/UDP frames

if UDP dst port == 7007, replies with the same payload

UDP ping client
cli_udp_ping.py:

creates a client endpoint

looks up the echo endpoint by name

sends one UDP payload ("marco polo" by default)

waits for the echo

You can override the ping message:

bash
Copy code
set PING_MSG=hello
python cli_udp_ping.py
(or PING_MSG=hello python cli_udp_ping.py on bash)

Extending Switchyard (recommended next steps)
Good next additions:

Sniffer tool (promiscuous subscriber) to print decoded frames

ARP microservice so clients can resolve MACs from IP (no hardcoded MACs)

NTP-lite responder (UDP/123)

Capture ring + replay in switchyardd.py

Impairments (drop/dup/reorder/latency) for deterministic “bad network” tests

Distributed firewall hooks (match/action rules at ingress)

Troubleshooting
“readexactly() called while another coroutine is already waiting…”
Fix: ensure you’re using the updated switchyard.py where only the background pump
reads from the socket and control replies are queued.

Client can’t find the service endpoint
Start the service (e.g. svc_echo.py) before the client, or add retry logic.

Port conflicts
Change the port in both daemon and clients (default 9999).

Notes / design goals
Keep the protocol stable so the fabric can be reimplemented later in C without changing tools.

Start simple and deterministic; bridge to real networking only when needed.

License
TBD (choose MIT/Apache-2.0/BSD-2-Clause, etc.)

pgsql
Copy code

If you want, I can also add a short “Roadmap” section tailored to your next three milestones (sniffer → ARP → NTP) and include the exact command lines for Windows + bash shells.
::contentReference[oaicite:0]{index=0}

## License

This project is licensed under the Apache License, Version 2.0.

You may obtain a copy of the License in the `LICENSE` file included in this repository or at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.




