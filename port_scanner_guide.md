# Building Your Own Python Port Scanner with Scapy
### A Complete Guide for Beginners — From Zero Networking Knowledge to a Working Tool

---

## Table of Contents

1. [What Is a Port Scanner and Why Build One?](#1-what-is-a-port-scanner-and-why-build-one)
2. [Networking Fundamentals You MUST Know](#2-networking-fundamentals-you-must-know)
3. [The TCP Handshake — The Heart of Port Scanning](#3-the-tcp-handshake--the-heart-of-port-scanning)
4. [Types of Port Scans](#4-types-of-port-scans)
5. [What Is Scapy?](#5-what-is-scapy)
6. [Your Learning Timeline (4 Weeks)](#6-your-learning-timeline-4-weeks)
7. [Setting Up Your Environment](#7-setting-up-your-environment)
8. [Week 1 Code — TCP Connect Scanner (Basics)](#8-week-1-code--tcp-connect-scanner-basics)
9. [Week 2 Code — SYN Stealth Scanner with Scapy](#9-week-2-code--syn-stealth-scanner-with-scapy)
10. [Week 3 Code — Full-Featured Scanner with Multiple Scan Types](#10-week-3-code--full-featured-scanner-with-multiple-scan-types)
11. [Week 4 Code — Banner Grabbing + Service Detection](#11-week-4-code--banner-grabbing--service-detection)
12. [Legal and Ethical Rules — READ THIS](#12-legal-and-ethical-rules--read-this)
13. [Glossary of Key Terms](#13-glossary-of-key-terms)

---

## 1. What Is a Port Scanner and Why Build One?

A **port scanner** is a program that probes a target computer to discover which network ports are open, closed, or filtered. Security professionals use them every day to:

- Audit their own infrastructure ("what services are exposed?")
- Find forgotten or misconfigured services
- Verify firewall rules are working
- Prepare for penetration tests

Building your own scanner — instead of just using Nmap — forces you to deeply understand how networks communicate, how protocols work at the packet level, and how security tools are engineered. It is one of the best hands-on exercises in cybersecurity.

---

## 2. Networking Fundamentals You MUST Know

### 2.1 The IP Address

Every device on a network has an **IP address** — a unique numerical label. Think of it like a home address on a street. Without it, no one can find you.

- Example IPv4 address: `192.168.1.1`
- Format: four numbers (0–255) separated by dots
- Your own machine is always reachable at `127.0.0.1` (called "localhost")

### 2.2 What Is a Port?

An IP address gets a packet to the *right machine*. A **port** gets it to the *right application* running on that machine.

Imagine a large apartment building. The IP address is the building address. The port number is the apartment number. The postman (the network) delivers to the building, and the right tenant (application) picks up the mail.

- Port numbers range from **0 to 65535**
- Ports 0–1023 are "well-known" ports reserved for standard services
- Ports 1024–49151 are "registered" ports used by applications
- Ports 49152–65535 are "dynamic/ephemeral" ports used temporarily

#### Common Well-Known Ports

| Port | Protocol | Service |
|------|----------|---------|
| 21   | TCP      | FTP (file transfer) |
| 22   | TCP      | SSH (secure shell) |
| 23   | TCP      | Telnet (old, insecure remote login) |
| 25   | TCP      | SMTP (sending email) |
| 53   | TCP/UDP  | DNS (domain name lookup) |
| 80   | TCP      | HTTP (web pages) |
| 443  | TCP      | HTTPS (secure web) |
| 3306 | TCP      | MySQL (database) |
| 3389 | TCP      | RDP (Windows remote desktop) |
| 8080 | TCP      | Alternative HTTP |

### 2.3 The OSI Model (Simplified)

Networks operate in layers. You don't need to memorize all 7, but you need to know these three for port scanning:

```
Layer 3 — Network Layer     → IP (Internet Protocol)
           Where am I sending this? → IP address

Layer 4 — Transport Layer   → TCP / UDP
           How am I sending this?   → Port numbers, reliability

Layer 7 — Application Layer → HTTP, SSH, FTP...
           What am I sending?       → The actual data/service
```

Scapy lets you craft packets at layers 3 and 4 directly — this is its superpower.

### 2.4 TCP vs UDP — The Two Main Protocols

**TCP (Transmission Control Protocol)**
- Reliable, ordered delivery
- Establishes a *connection* before sending data (the handshake)
- If a packet is lost, it is re-sent automatically
- Used by: HTTP, SSH, FTP, SMTP

**UDP (User Datagram Protocol)**
- "Fire and forget" — no connection, no guarantees
- Faster but unreliable
- No handshake — you just send
- Used by: DNS, video streaming, gaming, VoIP

---

## 3. The TCP Handshake — The Heart of Port Scanning

This is the most important concept for port scanning. TCP connections begin with a **three-way handshake**:

```
Client                          Server
  |                               |
  |  ——— SYN ——————————————————>  |   Step 1: "I want to connect"
  |                               |
  |  <—— SYN-ACK ———————————————  |   Step 2: "OK, I'm ready"  (PORT IS OPEN)
  |                               |
  |  ——— ACK ——————————————————>  |   Step 3: "Great, connected!"
  |                               |
```

Each message is called a **flag** inside the TCP packet header:

- **SYN** = Synchronize (initiate connection)
- **ACK** = Acknowledge (confirm receipt)
- **RST** = Reset (refuse or abort connection)
- **FIN** = Finish (close connection gracefully)

#### What Happens When a Port is OPEN vs CLOSED vs FILTERED?

```
OPEN:
  You ——— SYN ———> Server
  You <—— SYN-ACK — Server    ← Server responds positively

CLOSED:
  You ——— SYN ———> Server
  You <——— RST ———  Server    ← Server says "nothing here, go away"

FILTERED (firewall blocking):
  You ——— SYN ———> Server
  [no response / timeout]     ← Firewall silently drops your packet
```

This is exactly what your port scanner will detect. By sending a SYN and reading the response, you know the port state.

---

## 4. Types of Port Scans

### 4.1 TCP Connect Scan (Full Open Scan)
- Completes the full three-way handshake
- The OS does it for you using standard socket library
- **Loudest** — logged by most systems
- Easy to implement — good for learning first

### 4.2 SYN Scan (Half-Open / Stealth Scan)
- Sends SYN, gets SYN-ACK back, then sends RST instead of ACK
- **Never completes** the handshake — many systems don't log it
- Faster and stealthier than a full connect scan
- Requires root/admin privileges (you're crafting raw packets)
- This is Nmap's default scan — and what you'll build with Scapy

```
You ——— SYN ———> Target
You <—— SYN-ACK — Target   (port open!)
You ——— RST ———> Target     (abort before connection completes)
```

### 4.3 UDP Scan
- Sends empty UDP packet to target port
- If closed: receives ICMP "port unreachable" response
- If open: no response (or application-specific response)
- Slower and less reliable than TCP scans

### 4.4 FIN / NULL / XMAS Scans (Advanced)
- Send malformed TCP packets that bypass some firewalls
- On open ports: no response. On closed ports: RST
- Used to evade packet filters that only watch for SYN
- We'll cover these in Week 3

---

## 5. What Is Scapy?

Scapy is a powerful Python library that lets you **craft, send, sniff, and decode network packets** at a very low level. It gives you direct access to packet headers — IP layer, TCP layer, UDP layer — and lets you build packets from scratch, byte by byte.

Normal Python programs use "sockets" which are high-level abstractions. With Scapy, you go lower. You manually construct the IP header, the TCP header, set exactly which flags you want (SYN, FIN, etc.), and send the raw packet onto the wire.

### Why Scapy for a Port Scanner?

| Feature | Socket Library | Scapy |
|---------|---------------|-------|
| Full TCP handshake only | ✅ | ✅ |
| Half-open SYN scan | ❌ | ✅ |
| Custom TCP flags | ❌ | ✅ |
| Raw packet inspection | ❌ | ✅ |
| Packet sniffing | ❌ | ✅ |
| Learning value | Medium | Very High |

### Core Scapy Concepts

**Packet Layers**: In Scapy, you stack protocol layers using the `/` operator:
```python
packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
#         ^-- Layer 3: IP      ^-- Layer 4: TCP with SYN flag
```

**Key Functions**:
- `sr1()` — Send one packet, wait for one reply (returns the reply)
- `sr()` — Send packets, collect all replies
- `send()` — Send packet, don't wait for a reply
- `sniff()` — Passively capture packets from the network

**Key Packet Fields**:
```python
IP(dst="target_ip", ttl=64)         # Destination IP, time-to-live
TCP(dport=80, sport=12345, flags="S") # Destination port, source port, flags
UDP(dport=53)                         # UDP destination port
```

---

## 6. Your Learning Timeline (4 Weeks)

### Week 1 — Networking Basics + TCP Connect Scanner
**Goal**: Understand ports, TCP, and write your first working scanner using Python sockets.

- Study: IP addresses, ports, TCP handshake (sections 2 & 3 above)
- Practice: Use `telnet` or `nc` manually to connect to ports
- Code: TCP Connect scanner using Python's `socket` library
- Test: Scan your own machine (`127.0.0.1`)

**Milestone**: You can scan a list of ports on your own machine and see which are open.

---

### Week 2 — Scapy Fundamentals + SYN Scanner
**Goal**: Learn Scapy packet crafting. Build a SYN stealth scanner.

- Study: TCP flags (SYN, ACK, RST), Scapy packet syntax
- Practice: Craft packets in Scapy interactive shell, inspect them with `.show()`
- Code: SYN scanner with Scapy's `sr1()`
- Test: Scan your local network with explicit permission

**Milestone**: You can perform a SYN scan and correctly identify open vs closed vs filtered ports.

---

### Week 3 — Multiple Scan Types + Threading
**Goal**: Add UDP scanning, FIN/XMAS scans, and make it fast with threads.

- Study: UDP, ICMP, advanced TCP flags
- Code: Multi-type scanner with argument parsing (`argparse`)
- Add: Threading for speed (`concurrent.futures`)
- Add: Port range input, output formatting

**Milestone**: Your scanner accepts command-line arguments like `python scanner.py -t 192.168.1.1 -p 1-1000 --scan-type SYN`

---

### Week 4 — Banner Grabbing + OS Fingerprinting
**Goal**: Not just find open ports, but identify what service and version is running.

- Study: Application layer protocols (HTTP, SSH, FTP banners)
- Code: Banner grabbing (connect and read first response)
- Code: TTL-based OS fingerprinting
- Add: JSON/CSV output option
- Add: CIDR range scanning (scan entire subnet)

**Milestone**: Your scanner outputs service names, versions, and likely OS for each open port.

---

## 7. Setting Up Your Environment

### Requirements
- Python 3.8+
- **Linux or macOS strongly recommended** (SYN scan needs root; Windows has Scapy quirks)
- If on Windows: use WSL2 (Windows Subsystem for Linux)

### Installation

```bash
# Install Scapy
pip install scapy

# On Linux, you also need libpcap
sudo apt-get install python3-dev libpcap-dev   # Debian/Ubuntu
sudo dnf install libpcap-devel                 # Fedora/RHEL

# Verify installation
python3 -c "from scapy.all import *; print('Scapy OK')"
```

### Running Your Scanner
Most Scapy operations that send raw packets require **root/admin privileges**:
```bash
sudo python3 scanner.py
```

---

## 8. Week 1 Code — TCP Connect Scanner (Basics)

This scanner uses Python's built-in `socket` library — no Scapy yet. It completes the full TCP handshake.

```python
#!/usr/bin/env python3
"""
Week 1: TCP Connect Port Scanner
No Scapy needed — uses Python's built-in socket library.
Good for learning the basics before going raw.
"""

import socket
import sys
from datetime import datetime

# ─────────────────────────────────────────────
#  HOW IT WORKS:
#  socket.connect() does the full 3-way handshake.
#  If the handshake completes → port is OPEN.
#  If the server sends RST  → ConnectionRefusedError → port is CLOSED.
#  If nothing responds      → timeout → port is FILTERED.
# ─────────────────────────────────────────────

def scan_port(target_ip: str, port: int, timeout: float = 1.0) -> str:
    """
    Attempt a TCP connect to target_ip:port.
    Returns: "open", "closed", or "filtered"
    """
    try:
        # socket.AF_INET = use IPv4
        # socket.SOCK_STREAM = use TCP (stream-oriented)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set how long to wait before giving up (seconds)
        sock.settimeout(timeout)
        
        # Try to connect. Returns 0 on success.
        result = sock.connect_ex((target_ip, port))
        sock.close()
        
        if result == 0:
            return "open"      # Connection succeeded
        else:
            return "closed"    # Got a RST back

    except socket.timeout:
        return "filtered"      # No response → firewall probably dropped it

    except socket.error as e:
        return "closed"


def get_service_name(port: int) -> str:
    """Try to look up what service commonly runs on this port."""
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"


def scan_target(target: str, port_range: range, timeout: float = 1.0):
    """
    Scan a target IP across a range of ports.
    Prints results to screen.
    """
    # Resolve hostname to IP if needed (e.g. "google.com" → "142.250.x.x")
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve hostname: {target}")
        sys.exit(1)

    print("=" * 55)
    print(f" TCP Connect Scan — Target: {target_ip}")
    print(f" Ports: {port_range.start} - {port_range.stop - 1}")
    print(f" Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)

    open_ports = []

    for port in port_range:
        status = scan_port(target_ip, port, timeout)

        if status == "open":
            service = get_service_name(port)
            print(f"  [OPEN]     Port {port:5d}  →  {service}")
            open_ports.append(port)

        # Uncomment the lines below if you also want to see closed/filtered:
        # elif status == "closed":
        #     print(f"  [CLOSED]   Port {port:5d}")
        # elif status == "filtered":
        #     print(f"  [FILTERED] Port {port:5d}")

    print("=" * 55)
    print(f" Scan complete. {len(open_ports)} open port(s) found.")
    print("=" * 55)


# ─── ENTRY POINT ───────────────────────────────────────────
# Only runs when YOU execute this file directly (python3 scanner.py).
# If another script imports this file, this block is skipped — so your
# functions can be reused without triggering a scan automatically.
if __name__ == "__main__":
    # Scan your own machine — always safe and legal
    TARGET = "127.0.0.1"   # ← Change this to your target
    PORTS  = range(1, 1025) # Scan ports 1 through 1024

    scan_target(TARGET, PORTS)
```

**Try it yourself**: Run this against `127.0.0.1` (your own machine). Any services you have running (web server, SSH, database) will show as open.

---

## 9. Week 2 Code — SYN Stealth Scanner with Scapy

Now we go raw. This scanner crafts SYN packets manually and reads the TCP flags in the response to determine port state — without ever completing the handshake.

```python
#!/usr/bin/env python3
"""
Week 2: SYN Stealth Scanner with Scapy
Requires: sudo / root privileges
"""

import sys
import random
from scapy.all import IP, TCP, sr1, conf

# ─────────────────────────────────────────────
#  Suppress Scapy's verbose output
# ─────────────────────────────────────────────
conf.verb = 0  # 0 = silent, 1 = normal, 2 = verbose


def syn_scan_port(target_ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Send a SYN packet to target_ip:port.
    Read the response flags to determine port state.

    HOW IT WORKS:
    1. We craft: IP(dst=target) / TCP(dport=port, flags="S")
       - flags="S" means we ONLY set the SYN bit
    2. sr1() sends the packet and waits for ONE reply
    3. We inspect the reply's TCP flags:
       - SYN-ACK (0x12) → port is OPEN
       - RST-ACK (0x14) → port is CLOSED
       - No reply       → port is FILTERED
    """

    # Generate a random source port (1024–65535)
    # This mimics what a real OS would do
    src_port = random.randint(1024, 65535)

    # ── Build the packet ─────────────────────────────────
    # Layer 3: IP packet pointing at our target
    ip_layer = IP(dst=target_ip)

    # Layer 4: TCP segment
    #   dport = destination port (the one we're scanning)
    #   sport = source port (our random port)
    #   flags = "S" means only the SYN flag is set
    tcp_layer = TCP(dport=port, sport=src_port, flags="S")

    # Stack the layers: IP / TCP
    packet = ip_layer / tcp_layer
    # ─────────────────────────────────────────────────────

    # Send the packet and capture ONE response
    # timeout: how many seconds to wait before giving up
    response = sr1(packet, timeout=timeout)

    # ── Analyze the response ─────────────────────────────
    if response is None:
        # No response at all → firewall silently dropped our packet
        return "filtered"

    # Check if the response has a TCP layer
    if response.haslayer(TCP):
        tcp_flags = response[TCP].flags

        # TCP flags are bit flags. Common values:
        #   0x02 = SYN only
        #   0x12 = SYN + ACK  (binary: 00010010)  → OPEN
        #   0x14 = RST + ACK  (binary: 00010100)  → CLOSED
        #   0x04 = RST only                        → CLOSED

        if tcp_flags == 0x12:   # SYN-ACK
            # Port is OPEN! But we don't want to complete the handshake.
            # Send RST to politely abort the connection.
            rst_packet = IP(dst=target_ip) / TCP(dport=port, sport=src_port, flags="R")
            sr1(rst_packet, timeout=1)
            return "open"

        elif tcp_flags in (0x14, 0x04):  # RST-ACK or RST
            return "closed"

    # Caught an ICMP "unreachable" response (common for filtered ports)
    from scapy.all import ICMP
    if response.haslayer(ICMP):
        icmp_type = response[ICMP].type
        icmp_code = response[ICMP].code
        # ICMP type 3 = "Destination Unreachable"
        # codes 1,2,3,9,10,13 mean a firewall/admin is blocking it
        if icmp_type == 3 and icmp_code in (1, 2, 3, 9, 10, 13):
            return "filtered"

    return "unknown"


def syn_scan(target: str, ports: list, timeout: float = 2.0):
    """
    Run a SYN scan over a list of ports against the target.
    """
    import socket
    from datetime import datetime

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve: {target}")
        sys.exit(1)

    print("=" * 55)
    print(f" SYN Stealth Scan — Target: {target_ip}")
    print(f" Ports: {min(ports)} - {max(ports)}")
    print(f" Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)

    open_ports = []
    filtered_ports = []

    for port in ports:
        status = syn_scan_port(target_ip, port, timeout)

        if status == "open":
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            print(f"  [OPEN]     {port:5d}/tcp   {service}")
            open_ports.append(port)

        elif status == "filtered":
            filtered_ports.append(port)
            # Uncomment to see filtered ports:
            # print(f"  [FILTERED] {port:5d}/tcp")

    print("=" * 55)
    print(f" Open: {len(open_ports)} | Filtered: {len(filtered_ports)}")
    print("=" * 55)


# ─── ENTRY POINT ───────────────────────────────────────────
# Only runs when YOU execute this file directly (python3 scanner.py).
# If another script imports this file, this block is skipped — so your
# functions can be reused without triggering a scan automatically.
if __name__ == "__main__":
    # IMPORTANT: Only scan systems you own or have written permission to test!
    TARGET = "127.0.0.1"
    PORTS  = list(range(1, 1025))

    syn_scan(TARGET, PORTS)
```

---

## 10. Week 3 Code — Full-Featured Scanner with Multiple Scan Types

This version adds command-line arguments, threading for speed, and multiple scan types.

```python
#!/usr/bin/env python3
"""
Week 3: Full-Featured Port Scanner
Features:
  - SYN, TCP Connect, UDP scan types
  - Threading for parallel scanning
  - Command-line arguments (argparse)
  - Port range parsing (e.g. "22,80,443" or "1-1024")

Usage:
  sudo python3 scanner_v3.py -t 192.168.1.1 -p 1-1024 --type SYN
  sudo python3 scanner_v3.py -t 192.168.1.1 -p 22,80,443 --type TCP
"""

import argparse
import socket
import sys
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from scapy.all import IP, TCP, UDP, ICMP, sr1, conf

conf.verb = 0  # Silent mode


# ═══════════════════════════════════════════════════════════
#  SCAN FUNCTIONS
# ═══════════════════════════════════════════════════════════

def tcp_connect_scan(ip: str, port: int, timeout: float = 1.0) -> tuple:
    """Full TCP connect scan using Python sockets."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        status = "open" if result == 0 else "closed"
    except socket.timeout:
        status = "filtered"
    except:
        status = "closed"
    return (port, status, "TCP")


def syn_scan(ip: str, port: int, timeout: float = 2.0) -> tuple:
    """SYN stealth scan using raw packets via Scapy."""
    src_port = random.randint(1024, 65535)
    packet = IP(dst=ip) / TCP(dport=port, sport=src_port, flags="S")
    response = sr1(packet, timeout=timeout)

    if response is None:
        return (port, "filtered", "SYN")

    if response.haslayer(TCP):
        flags = response[TCP].flags
        if flags == 0x12:  # SYN-ACK
            rst = IP(dst=ip) / TCP(dport=port, sport=src_port, flags="R")
            sr1(rst, timeout=1)
            return (port, "open", "SYN")
        elif flags in (0x14, 0x04):
            return (port, "closed", "SYN")

    if response.haslayer(ICMP):
        if response[ICMP].type == 3 and response[ICMP].code in (1,2,3,9,10,13):
            return (port, "filtered", "SYN")

    return (port, "unknown", "SYN")


def udp_scan(ip: str, port: int, timeout: float = 2.0) -> tuple:
    """
    UDP scan: send empty UDP packet, watch for ICMP "port unreachable".

    UDP is tricky:
    - OPEN ports often don't respond at all (no response = likely open)
    - CLOSED ports return ICMP type 3 code 3 ("port unreachable")
    - FILTERED ports return other ICMP unreachable codes
    """
    packet = IP(dst=ip) / UDP(dport=port)
    response = sr1(packet, timeout=timeout)

    if response is None:
        # No response: UDP port is likely open OR filtered
        # We call it "open|filtered" because we can't be sure
        return (port, "open|filtered", "UDP")

    if response.haslayer(UDP):
        # Got a UDP response → definitely open
        return (port, "open", "UDP")

    if response.haslayer(ICMP):
        icmp = response[ICMP]
        if icmp.type == 3:
            if icmp.code == 3:
                return (port, "closed", "UDP")   # Port unreachable
            elif icmp.code in (1, 2, 9, 10, 13):
                return (port, "filtered", "UDP") # Admin prohibited

    return (port, "unknown", "UDP")


# ═══════════════════════════════════════════════════════════
#  PORT RANGE PARSER
# ═══════════════════════════════════════════════════════════

def parse_ports(port_string: str) -> list:
    """
    Parse a port string into a list of integers.
    Examples:
      "80"          → [80]
      "22,80,443"   → [22, 80, 443]
      "1-1024"      → [1, 2, 3, ..., 1024]
      "22,80,100-200" → [22, 80, 100, 101, ..., 200]
    """
    ports = []
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))  # Remove duplicates, sort


# ═══════════════════════════════════════════════════════════
#  MAIN SCANNER
# ═══════════════════════════════════════════════════════════

def run_scan(target: str, ports: list, scan_type: str, threads: int, timeout: float):
    """
    Orchestrates the scan using a thread pool.

    Threading explanation:
    Without threads: scan 1000 ports × 1 second timeout = ~1000 seconds
    With 100 threads: 1000 ports / 100 threads = ~10 seconds
    ThreadPoolExecutor manages a pool of worker threads for us.
    """
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve: {target}")
        sys.exit(1)

    # Select the right scan function
    scan_function = {
        "SYN": syn_scan,
        "TCP": tcp_connect_scan,
        "UDP": udp_scan,
    }[scan_type]

    print("\n" + "═" * 60)
    print(f"  Target    : {target_ip}")
    print(f"  Scan Type : {scan_type}")
    print(f"  Ports     : {len(ports)} ({min(ports)}–{max(ports)})")
    print(f"  Threads   : {threads}")
    print(f"  Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 60)

    results = []

    # ThreadPoolExecutor: run up to `threads` tasks in parallel
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all port scan jobs to the thread pool
        # Each future represents a pending result
        futures = {
            executor.submit(scan_function, target_ip, port, timeout): port
            for port in ports
        }

        # as_completed() yields futures as they finish (not in order)
        for future in as_completed(futures):
            try:
                port, status, proto = future.result()
                results.append((port, status, proto))
            except Exception as e:
                port = futures[future]
                results.append((port, "error", scan_type))

    # Sort results by port number before printing
    results.sort(key=lambda x: x[0])

    open_count = 0
    for port, status, proto in results:
        if status == "open" or status == "open|filtered":
            try:
                service = socket.getservbyport(port, proto.lower())
            except:
                service = "unknown"
            print(f"  [{status.upper():15s}] {port:5d}/{proto.lower():<4s}  {service}")
            open_count += 1

    print("═" * 60)
    print(f"  Scan complete. {open_count} open/open|filtered port(s) found.")
    print("═" * 60 + "\n")


# ═══════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Python Port Scanner using Scapy",
        epilog="Example: sudo python3 scanner_v3.py -t 192.168.1.1 -p 1-1024 --type SYN"
    )
    parser.add_argument("-t", "--target",   required=True,        help="Target IP or hostname")
    parser.add_argument("-p", "--ports",    default="1-1024",     help="Port range, e.g. 22,80,100-200")
    parser.add_argument("--type",           default="SYN",
                        choices=["SYN", "TCP", "UDP"],            help="Scan type (default: SYN)")
    parser.add_argument("--threads",        type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--timeout",        type=float, default=2.0, help="Timeout per port in seconds")

    args = parser.parse_args()

    ports = parse_ports(args.ports)
    run_scan(args.target, ports, args.type, args.threads, args.timeout)


# Only runs when YOU execute this file directly (python3 scanner.py).
# If another script imports this file, this block is skipped — so your
# functions can be reused without triggering a scan automatically.
if __name__ == "__main__":
    main()
```

---

## 11. Week 4 Code — Banner Grabbing + Service Detection

Banner grabbing means connecting to an open port and reading whatever the service sends first — the "banner". Most services announce themselves: SSH sends `SSH-2.0-OpenSSH_8.9`, HTTP servers send headers, FTP sends `220 FTP server ready`.

```python
#!/usr/bin/env python3
"""
Week 4: Banner Grabbing Module
Attach this to your scanner to identify services and versions.
"""

import socket
import ssl


def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    """
    Connect to ip:port and read the first response (the banner).
    Tries plain TCP first, then SSL/TLS.
    Returns the banner string or empty string if nothing received.
    """

    # ── Method 1: Plain TCP ──────────────────────────────
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Some services (HTTP) need a prompt before they respond
        # Send a generic HTTP request to trigger a response
        if port in (80, 8080, 8443, 443):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        else:
            # For SSH, FTP, SMTP, etc. — they send a banner immediately
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()

        if banner:
            return banner

    except:
        pass

    # ── Method 2: SSL/TLS (for HTTPS and similar) ───────
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=ip) as ssl_sock:
                ssl_sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = ssl_sock.recv(1024).decode("utf-8", errors="ignore").strip()
                return f"[TLS] {banner}"
    except:
        pass

    return ""


def identify_service(banner: str, port: int) -> dict:
    """
    Try to identify the service and version from the banner text.
    Returns a dict with 'service' and 'version' keys.
    """
    banner_lower = banner.lower()
    result = {"service": "unknown", "version": ""}

    # SSH
    if banner.startswith("SSH-"):
        result["service"] = "SSH"
        result["version"] = banner.split("\n")[0]

    # FTP
    elif "ftp" in banner_lower or banner.startswith("220"):
        result["service"] = "FTP"
        result["version"] = banner.split("\n")[0]

    # SMTP
    elif "smtp" in banner_lower or ("220" in banner and "mail" in banner_lower):
        result["service"] = "SMTP"
        result["version"] = banner.split("\n")[0]

    # HTTP
    elif "http" in banner_lower or "server:" in banner_lower:
        result["service"] = "HTTP"
        for line in banner.split("\n"):
            if line.lower().startswith("server:"):
                result["version"] = line.split(":", 1)[1].strip()
                break

    # MySQL
    elif port == 3306:
        result["service"] = "MySQL"
        result["version"] = banner[:50]

    return result


def scan_with_banners(ip: str, open_ports: list):
    """
    Given a list of open ports, grab banners and print a rich report.
    """
    print(f"\n{'═' * 65}")
    print(f"  BANNER GRABBING RESULTS — {ip}")
    print(f"{'═' * 65}")
    print(f"  {'PORT':<8} {'SERVICE':<12} {'BANNER / VERSION'}")
    print(f"  {'-'*7} {'-'*11} {'-'*42}")

    for port in open_ports:
        banner = grab_banner(ip, port)
        info = identify_service(banner, port)

        # Truncate long banners for display
        display_banner = (banner[:50] + "...") if len(banner) > 50 else banner
        display_banner = display_banner.replace("\r", "").replace("\n", " | ")

        print(f"  {port:<8} {info['service']:<12} {display_banner or '(no banner)'}")

    print(f"{'═' * 65}\n")


# ─── EXAMPLE USAGE ─────────────────────────────────────────
# Only runs when YOU execute this file directly (python3 scanner.py).
# If another script imports this file, this block is skipped — so your
# functions can be reused without triggering a scan automatically.
if __name__ == "__main__":
    TARGET = "127.0.0.1"

    # Simulate having found these open ports from your scanner:
    open_ports = [22, 80, 443, 3306]

    scan_with_banners(TARGET, open_ports)
```

---

## 12. Legal and Ethical Rules — READ THIS

> ⚠️ Port scanning systems you do not own or do not have **explicit written permission** to test is **illegal** in most jurisdictions — including the US (Computer Fraud and Abuse Act), the EU, and the UK.

### What You CAN always scan safely:

- `127.0.0.1` — your own machine (localhost)
- Your own home lab (VMs, Raspberry Pi you own)
- Intentionally vulnerable VMs: **Metasploitable**, **VulnHub**, **HackTheBox** (with active subscription), **TryHackMe**

### What you CANNOT scan without permission:

- Public websites, servers, cloud services
- Your company's network (unless you're the sysadmin and have documented authorization)
- Any IP you don't own

### Recommended Safe Practice Labs:

- **TryHackMe** (tryhackme.com) — beginner-friendly, browser-based
- **HackTheBox** (hackthebox.com) — more advanced
- **Metasploitable** — intentionally vulnerable Linux VM, run locally
- Set up a **home lab** with VirtualBox + Linux VMs

---

## 13. Glossary of Key Terms

| Term | Meaning |
|------|---------|
| IP Address | Unique numerical label for a device on a network |
| Port | Logical endpoint for a network connection (0–65535) |
| TCP | Transmission Control Protocol — reliable, connection-based |
| UDP | User Datagram Protocol — fast, connectionless |
| SYN | TCP synchronize flag — starts a connection |
| ACK | TCP acknowledge flag — confirms receipt |
| RST | TCP reset flag — aborts connection |
| FIN | TCP finish flag — closes connection gracefully |
| Handshake | The SYN → SYN-ACK → ACK exchange that establishes TCP |
| Raw Socket | Low-level socket giving direct access to packet headers |
| Scapy | Python library for crafting and sending raw packets |
| Banner | The first message a service sends when you connect to it |
| ICMP | Internet Control Message Protocol — used for ping, error messages |
| TTL | Time To Live — how many network hops a packet can traverse |
| Firewall | System that filters network traffic based on rules |
| Open Port | Port with a service actively listening for connections |
| Closed Port | Port with no service, but machine responds with RST |
| Filtered Port | Port blocked by firewall — no response at all |

---

*Guide written for educational purposes. Only scan systems you own or have explicit permission to test.*
