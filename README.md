# PCAPture

A lightweight **packet sniffer** written in C using **libpcap/Npcap**.  
Capture and analyze network traffic in real-time, with support for Ethernet, IP, TCP/UDP parsing.

## Features
- Capture raw packets from any network interface
- Parse Ethernet, IP, TCP, UDP, and ICMP headers
- Apply basic filters (IP, port, protocol)
- Save captured packets to `.pcap` files for later analysis

## Requirements
- **Linux:** libpcap-dev (`sudo apt install libpcap-dev`)  
- **Windows:** Npcap SDK

## Build & Run (Linux)
```bash
gcc src/main.c -o pcapTURE -lpcap
sudo ./pcapTURE
