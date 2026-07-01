# PCAP File Parser

A C program that reads and parses `.pcap` files without using libpcap. Reads raw bytes directly and decodes Ethernet and IPv4 headers packet by packet.

## Build

## Run

## What it does

- Validates the pcap global header magic number
- Walks through each packet record in the file
- Parses Ethernet headers: source/destination MAC and EtherType
- For IPv4 packets (EtherType 0x0800): prints source/destination IP, TTL, protocol, and IHL
- Unknown EtherTypes are printed in hex and skipped cleanly

## What was hard

Endianness was the trickiest part — pcap files store multi-byte fields in host byte order while network protocol fields are big-endian, so knowing when to use `ntohs()` and when not to took careful thought. Handling unknown EtherTypes cleanly (printing the hex value and skipping rather than crashing) also required understanding that not every packet on a real network will be IPv4.
