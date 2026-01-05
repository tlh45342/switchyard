# Switchyard Virtual Network Fabric

Switchyard is a lightweight, deterministic virtual network fabric designed for VM experimentation, protocol testing, and educational networking work. It provides a simple message-based protocol for creating virtual Ethernet endpoints and exchanging raw frames between them, enabling you to build small, controlled network topologies without relying on real NICs or OS-level networking.

---

## Features

- Deterministic virtual network fabric
- Multiple virtual Ethernet endpoints per client
- Simple, documented wire protocol
- ARP responder microservice
- NTP responder microservice
- UDP echo and UDP ping examples
- Easy to extend with additional protocol services
- Clean Python reference implementation

---

## Quick Start

```bash
git clone https://github.com/<yourname>/switchyard
cd switchyard
python3 switchyardd.py
```

Then, in another terminal:

```bash
python3 cli_ntp.py
```

Or try the UDP echo service:

```bash
python3 svc_echo.py
python3 cli_udp_ping.py
```

---

## Architecture Overview

Switchyard uses a simple client–server model:

```
+------------------+        +------------------+
|   cli_ntp.py     | <----> |   switchyardd    |
+------------------+        +------------------+
           ^                         |
           |                         v
+------------------+        +------------------+
|   svc_ntp.py     | <----> |   switchyardd    |
+------------------+        +------------------+
```

- **switchyardd.py** — the fabric daemon; manages endpoints and frame delivery  
- **switchyard.py** — protocol definitions and client SDK  
- **svc_ntp.py** — NTP responder microservice  
- **cli_ntp.py** — NTP client  
- **svc_echo.py** — UDP echo service  
- **cli_udp_ping.py** — UDP ping client  

---

## Protocol Summary

Switchyard uses a simple binary protocol with a length prefix and message header.

| Message Type       | Purpose                                  |
|--------------------|-------------------------------------------|
| HELLO              | Client announces itself                   |
| WELCOME            | Server assigns client ID                  |
| ENDPOINT_CREATE    | Client requests a new virtual endpoint    |
| ENDPOINT_CREATED   | Server confirms endpoint creation         |
| PACKET_IN          | Client sends an Ethernet frame to fabric  |
| PACKET_OUT         | Fabric delivers a frame to a client       |
| ERROR              | Error or invalid request                  |

The protocol is intentionally minimal to keep implementations simple and hackable.

---

## Example: NTP Service

Start the fabric:

```bash
python3 switchyardd.py
```

Start the NTP service:

```bash
python3 svc_ntp.py
```

Query it:

```bash
python3 cli_ntp.py
```

You’ll receive a valid NTP response generated entirely inside the virtual fabric.

---

## Roadmap

- [ ] TAP/Npcap bridge for real NIC integration  
- [ ] Packet impairment (latency, jitter, drop)  
- [ ] DHCP microservice  
- [ ] Wireshark capture export  
- [ ] C rewrite of the fabric core  
- [ ] Multi-client topologies  
- [ ] IPv6 support  

---

## Why This Exists

Switchyard was created to provide a deterministic, lightweight virtual network fabric for VM and emulator development. Existing tools were either too heavy, too opaque, or too tied to real network interfaces. This project aims to be simple, hackable, and educational — a foundation for experimenting with network protocols and microservices.

---

## Contributing

Pull requests are welcome.  
If you plan to make significant changes, please open an issue first to discuss your ideas.

---

## License

This project is licensed under the Apache License, Version 2.0.

You may obtain a copy of the License in the `LICENSE` file included in this repository or at:

http://www.apache.org/licenses/LICENSE-2.0

See the NOTICE file for attribution information.
