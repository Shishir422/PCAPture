# PCAPture

**PCAPture** is a lightweight packet sniffer written in **C** using **raw sockets** on Linux.  
It captures live network traffic and parses Ethernet, IP, TCP, UDP, and ICMP headers, printing them in real-time.  

Think of it as a hands-on, minimal **Wireshark‑lite**, built from scratch for learning and exploration of how packets really look at the byte level.

---

## ✨ Features
- Capture raw packets directly from the network interface  
- Parse and display:  
  - Ethernet headers (source/destination MAC, protocol)  
  - IP headers (source/destination IP, protocol)  
  - TCP/UDP headers (source/destination ports)  
  - ICMP headers (type)  
- Continuous capture loop until interrupted (`Ctrl+C`)  
- Modular and extensible code structure (`main.c`, `capture.c`, `parser.c`)  

---

## 🛠️ Requirements
- **Linux** (Kali, Ubuntu, Debian, Fedora, etc.)  
- Root privileges (raw sockets require elevated rights)  
- Development tools:
  ```bash
  sudo apt update
  sudo apt install build-essential