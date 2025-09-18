
# Implementation Notes & Design Decisions

Author: Lilah Dicker

This document explains the code paths, helper functions, and debugging decisions behind the software router implementation.

## Entry & Demux

- Start in `sr_handlepacket()` (in `sr_router.c`), where I classify frames into ARP vs. IP and delegate:
  - `handle_arp_packet(...)`
  - `handle_ip_packet(...)`

This early split made it easier to debug misclassification issues.

## IP Path (`handle_ip_packet`)
1. Parse Ethernet/IP headers; validate checksum (drop if invalid).
2. Check if `dst_ip` matches any router interface:
   - If **for router**:
     - If ICMP Echo Request (Type 8), send Echo Reply via `icmp_echo_reply(...)`.
     - Otherwise, return ICMP Port Unreachable (Type 3, Code 3).
   - If **to be forwarded**:
     - Decrement TTL; if TTL hits 0, send ICMP Time Exceeded (Type 11, Code 0).
     - Recompute IP checksum.
     - Find next hop via **Longest Prefix Match** `find_longest_prefix_match(...)`.
       - If no route, ICMP Dest Network Unreachable (Type 3, Code 0).
       - Else determine next-hop (gateway or dst directly).
     - If next-hop MAC is cached (`sr_arpcache_lookup`): set L2 addrs and `sr_send_packet`.
     - Else queue packet and trigger ARP (`sr_arpcache_queuereq`).

> I added guards to avoid self-forwarding loops detected during debugging.

## ARP Path (`handle_arp_packet`)
- Verify packet addressed to this router.
- **ARP Request**: construct and send ARP Reply using current interface MAC/IP.
- **ARP Reply**:
  - Insert into cache (`sr_arpcache_insert`).
  - Drain corresponding request queue: fill dest MAC for each queued packet and `sr_send_packet`, then remove the req.

## ARP Retries & Timeouts
- `arpcache_sweepreqs()` iterates unresolved requests and calls `handle_arpreq(req)`:
  - If <5 requests sent and 1s elapsed, resend ARP request.
  - After 5 attempts, send ICMP Dest Host Unreachable (Type 3, Code 1) for each queued packet and remove the request.

## ICMP Helpers
- `icmp_echo_reply(...)`: allocate buffer, copy payload, swap src/dst, set Type 0, recompute checksums, route back using LPM.
- `send_icmp_error(type, code, ...)`: construct Ethernet + IP + ICMP (including original IP header + 8 bytes), compute checksums, choose source interface, and send.

## Longest Prefix Match
- Iterate routing table entries; for each, compare `(dst_ip & mask) == (route_dest & mask)`.
- Keep the match with the **longest mask** (most specific).
- Return route or `NULL` → generates dest net unreachable.

## Debugging Notes
- Early on I saw intermittent ping loss across subnets; this matched expected behavior when ARP was not yet resolved (first echo timed out), then succeeded once cached.
- Traceroute initially showed `***`; fixed ICMP Time Exceeded generation, then saw expected hop responses.
- Verified Dest Net Unreachable by ensuring LPM returns `NULL`; verified Host Unreachable after 5 ARP retries.
- Confirmed Port Unreachable for non-ICMP packets destined to router.
- Added print statements throughout to verify control flow and timing.

## Files Modified / Key Logic
- `sr_router.c`: `sr_handlepacket`, `handle_ip_packet`, `handle_arp_packet`, ICMP helpers, LPM helper.
- `sr_arpcache.c`: `arpcache_sweepreqs`, `handle_arpreq`, queue management.
- `sr_utils.c`: checksum helpers, dumps.

## Known Edge Cases / Guards
- Self-forwarding/loop guards.
- Strict checksum verification before processing.
- TTL decrement occurs prior to forwarding; error path handled early for clarity.
