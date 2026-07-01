# PCAP File Parser

A lightweight pcap file parser written in C that decodes network packet captures without using libpcap. Reads raw bytes directly from `.pcap` files and decodes Ethernet and IPv4 headers packet by packet.

## Features

- Validates pcap global header magic number (supports both endian formats)
- Walks through all packet records in the file
- Ethernet header parsing: source/destination MAC addresses and EtherType
- IPv4 header parsing: source/destination IP, TTL, protocol, and IHL
- IHL (Internet Header Length) correctly calculated from raw 4-bit field
- Unknown EtherTypes printed in hex and skipped cleanly — no crashes on mixed traffic
- No external dependencies — pure C, raw byte parsing only

## Requirements

- Linux or macOS
- GCC

## Build

```bash
gcc pcap_parse.c -o pcap_parse
```

## Run

```bash
./pcap_parse <filename.pcap>
```

## Generate a test pcap

```bash
sudo tcpdump -i any -c 20 -w sample.pcap
```

## Example Output
Packet 1: len=98
a2:9a:8e:d4:dc:64
src: ea:47:c4:65:2a:9c
EtherType : 0x0800
Src IP: 192.168.64.2
Dst IP: 142.251.43.14
TTL: 64
Protocol: 1
IHL: 20 bytes
Packet 2: len=48
08:06:00:00:00:00
src: 00:02:00:01:04:06
EtherType : 0xa29a
Unknown EtherType: 0xa29a, skipping

## What was hard

Endianness was the trickiest part — pcap files store multi-byte fields in host byte order while network protocol fields are big-endian, so knowing exactly when to apply `ntohs()` required careful thought. Handling unknown EtherTypes cleanly (printing the hex value and skipping rather than crashing) also required understanding that real-world network captures contain far more than just IPv4 traffic.
