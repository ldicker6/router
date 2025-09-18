# Software Router (C)

A user-space software router implemented in C. It parses Ethernet frames, handles ARP, forwards IPv4 packets with longest-prefix match, and generates required ICMP messages (echo reply, time exceeded, destination/port unreachable). Built as part of a computer networks course, presented here as a standalone, runnable project.

## ✨ Features
- **Ethernet → ARP/IP demux** with header parsing/validation
- **ARP cache & request queue** (timeouts, retries; queue drain on reply)
- **IPv4 forwarding** with **longest-prefix match (LPM)** and TTL/checksum updates
- **ICMP**: echo reply, time exceeded (TTL=0), dest net/host unreachable, port unreachable
- **Robust error handling** and packet utilities

## 🔧 Tech & Skills
C (GCC), Linux networking, packet parsing, routing algorithms, debugging (tcpdump/Wireshark), build systems (Make).

## 📁 Project Layout
```bash
.
├── Makefile               # build instructions
├── README.md              # project overview
├── rtable                 # example static routing table
├── sha1.c / sha1.h        # SHA1 utilities
├── sr_arpcache.c / .h     # ARP cache & request queue
├── sr_dumper.c / .h       # packet dumping utilities
├── sr_if.c / .h           # router interface utilities
├── sr_main.c              # router entry point (main loop)
├── sr_protocol.h          # on-wire protocol definitions (Ethernet/IP/ARP/ICMP)
├── sr_router.c / .h       # core router logic, packet processing
├── sr_rt.c / .h           # routing table helpers
├── sr_utils.c / .h        # checksum, printing, misc utils
├── sr_vns_comm.c          # virtual network server comms
└── vnscommand.h           # VNS command definitions
```

--- 

## ▶️ Build
Tested on Ubuntu.
```bash
sudo apt-get update && sudo apt-get install -y build-essential
make clean && make
```

## Quick Functional Checks

Ping the router interface → ICMP echo reply:
```bash
$ ping <router-if-ip>
```

Ping across subnets → triggers ARP resolution + forwarding:
```bash
$ ping <host-in-other-subnet>
```

Traceroute → observe ICMP Time Exceeded at decreasing TTL:
```bash
$ traceroute <remote-host>
```

- No route → ICMP Dest Net Unreachable (Type 3, Code 0)
- ARP exhaust (5 retries) → ICMP Dest Host Unreachable (Type 3, Code 1)
- UDP to router (non-ICMP) → ICMP Port Unreachable (Type 3, Code 3)
---

## Design Overview

- Packet entry: sr_handlepacket() splits ARP vs IP.
- IP handling (handle_ip_packet): checksum verify → local vs forward → TTL/cksum update → LPM → send or ARP queue.
- ARP handling (handle_arp_packet): reply when requested; on reply, insert into cache and flush queued packets.
- ARP retries: arpcache_sweepreqs() + handle_arpreq() manage timeouts and eventual host-unreachable ICMP.
- ICMP helpers: icmp_echo_reply(...) and send_icmp_error(type, code, ...) centralize construction & checksums.

For the full deep-dive (files modified, helpers, debugging notes, design decisions), see [docs/IMPLEMENTATION.md](https://github.com/ldicker6/router/blob/main/IMPLEMENTATION.md)

---

### Future Improvements

- Add NAT for private ↔ public translation
- Dynamic routing (RIP/OSPF) alongside static LPM
- Structured logging & packet visualization
- Integrate PCAP playback/tests; automated LPM unit tests
