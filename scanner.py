# ----------------- <rules> ------------------
#function names: snake_case
#variable names: camelCase


# ----------------- </rules> ------------------


# ----------------- <import> -----------------
import argparse
import random
import socket
import sys
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, UDP, ICMP, sr1, conf

# ----------------- </import> -----------------


# ----------------- <functions> -----------------

#───── <SCANNER> ────────────────
# TODO: Function SCANNER --type SYN
#target ip (string), port (list), timeout (float, default= 1.0), sleep_timer (float, random number between 2.0-30.0 or user input)
def scan_syn(
        target_ip: str,
        port: int,
        sleep_timer: float,
        timeout: float = 1.0 ) -> tuple[int, bool]: #returns bool and port

    tcp_packet = IP(dst=target_ip) / TCP(dport=port, flags="S") #Zieladresse and header
    resp = sr1(
        tcp_packet, #sends and waits for one answer
        timeout=timeout, #max wait time
        verbose=False)  #verbose stops standard scapy return

    time.sleep(sleep_timer)

    if (resp is not None #at least one answer
            and resp.haslayer(TCP)  #real tcp answer, SYN/ACK oder RST/ACK
            and resp.getlayer(TCP).flags == 0x12):  #0x12: SYN + ACK (SYN/ACK) -> port open
        return port, True

    return port, False
# -----------------------oder------------------------------
    # open_ports: list[int] = []
    # other_ports: list[int] = [] #closed, filtered, no answer
    #
    #
    # tcp_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
    #
    # #Send and wait for response
    # resp = sr1(tcp_packet, timeout=timeout, verbose=False) #verbose stops standard scapy return
    # #returns none (no answer during timeout), resp
    # if resp is None:
    #      # no response → filtered / dropped / host down
    #     other_ports.append(port)    #sorts into list
    #
    # elif resp.haslayer(TCP):
    #     flags = resp.getlayer(TCP).flags
    #
    #     if flags == 0x12:  # SYN/ACK -> acknowledgement ist there -> Port open & accepts
    #         open_ports.append(port) #sorts into list
    #     else:
    #          # RST/ACK or other flags → not open
    #         other_ports.append(port)
    #
    # else: # resp is not none and no tcp layer
    #     other_ports.append(port)
    #
    # time.sleep(sleep_timer)
    #
    # return open_ports, other_ports
# -----------------------/oder------------------------------




# TODO: TCP Connect SCAN --type TCP

# TODO: UDP SCAN --type UDP



#udp_scanner
def scan_udp(target:str,ports:list[int],sleep_timer:float):
    for port in ports:
        sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(sleep_timer)
        try:
            sock.sendto(b"test", (target, port))

            data, addr = sock.recvfrom(1024)

            print(f"[OPEN] UDP {port}")
        except socket.timeout:
            print(f"[NO RESPONSE] UDP {port}")

        except Exception as e:
            print(f"[ERROR] UDP {port}: {e}")

        finally:
            sock.close()
#───── </SCANNER> ────────────────

# TODO: Output to JSON

# target IP from file
def load_targets_from_file(filepath: str) -> list:
    """
    Read a .txt file and return a list of IP addresses / hostnames.\n

    Expected file format — one target per line:
        192.168.1.1\n
        192.168.1.2\n
        scanme.nmap.org\n

    Lines starting with # are treated as comments and ignored.
    Empty lines are also ignored.
    """
    targets = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()  # remove spaces and newlines
                if line and not line.startswith("#"):  # skip empty lines and comments
                    targets.append(line)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Cannot read file (permission denied): {filepath}")
        sys.exit(1)

    if not targets:
        print(f"[ERROR] No valid targets found in file: {filepath}")
        sys.exit(1)

    return targets

# port parser
def parse_ports(ports: str) -> list[int]:
    result = set()

    for part in ports.split(","):           #Splits the String in single entities
        part = part.strip()                 #Removes blankspace in front and back of the numbers

        if "-" in part:                     #Checks if there is a Range
            start, end = part.split("-")

            start = int(start)
            end = int(end)

            if start > end:                 #Checks if the User tipped a Range with the higher number at start
                start, end = end, start

            result.update(range(start, end + 1))

        else:
            result.add(int(part))

    return sorted(result)

# run_scan
def run_scan(target: str, ports: list, type: str,threads: int, timeout: float, sleep_time: float = random.uniform(2.0, 30.0)) -> None:
    """
    function takes target IP as STRING, ports as LIST, type as STRING, sleep_time as FLOAT
    """

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve: {target}")
        sys.exit(1)

    # select scan function
    scan_function = {
        "SYN": scan_syn,
        "TCP": scan_tcp,
        "UDP": scan_udp,
    }[type]

    # User notification on CLI

    print("\n" + "=" * 60)
    print(f"  Target    : {target_ip}")
    print(f"  Scan Type : {type}")
    if len(ports) > 10:
        print(f"  Ports     : {len(ports)} ({min(ports)}–{max(ports)})")
    else:
        print(f"  Ports     : {ports})")
    print(f"  Threads   : {threads}")
    print("\n" + "=" * 60)

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
                results.append((port, "error", type))

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

# ----------------- </functions> -----------------

# ----------------- <MAIN> -----------------

def main():
    parser = argparse.ArgumentParser(
        description="Python Port Scanner using Scapy",
        epilog=(
            "Examples - Linux:\n"
            "  sudo python3 scanner_v3.py -t 192.168.1.1 -p 1-1024 --type SYN\n"
            "  sudo python3 scanner_v3.py -f targets.txt -p 22,80,443 --type TCP"
        ),
        formatter_class=argparse.RawTextHelpFormatter  # preserves newlines in epilog
    )

    # ── Target options — user must provide ONE of these, not both ──
    target_group = parser.add_mutually_exclusive_group(required=True)
    #   add_mutually_exclusive_group(required=True) means:
    #   - the user MUST provide at least one of the arguments in this group
    #   - but providing BOTH at the same time is an error
    #   - argparse enforces this automatically and prints a helpful error message

    target_group.add_argument(
        "-t", "--target",
        help="Single target IP or hostname  (e.g. 192.168.1.1)"
    )
    target_group.add_argument(
        "-f", "--file",
        help="Path to a .txt file with one IP/hostname per line  (e.g. targets.txt)"
    )

    # ── Other options (unchanged) ──────────────────────────────────
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range, e.g. 22,80,100-200  (default: 1-1024)")
    parser.add_argument("--type", default="SYN", choices=["SYN", "TCP", "UDP"], help="Scan type  (default: SYN)")
    parser.add_argument("--port-randomize", help="if used the order of the ports  will be randomized", action="store_true")
    parser.add_argument("-s", "--sleep", default=2.0 , type=float, help="Sleep time in seconds (default: RANDOM range: 2-)")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout per port in seconds")
    args = parser.parse_args()

    # ── Build the target list ──────────────────────────────────────
    if args.file:
        # User passed a file — load all IPs from it
        targets = load_targets_from_file(args.file)
        print(f"[INFO] Loaded {len(targets)} target(s) from {args.file}")
    else:
        # User passed a single -t target — wrap it in a list
        # so the loop below works the same way for both cases
        targets = [args.target]

    # ── Parse ports once (same for all targets) ───────────────────
    ports = parse_ports(args.ports)

    # ── Randomize port order if flag was set ──────────────────────
    # args.port_randomize is True if user passed --port-randomize, False if not.
    # Note: argparse converts hyphens to underscores → --port-randomize becomes args.port_randomize
    if args.port_randomize:
        random.shuffle(ports)  # shuffle() modifies the list in place — no new list created
        print(f"[INFO] Port order randomized")

    # ── Scan each target ──────────────────────────────────────────
    for target in targets:
        run_scan(target, ports, args.type, args.threads, args.timeout, args.sleep)

# ----------------- </MAIN> -----------------

"""
Only runs when YOU execute this file directly (python3 scanner.py).
If another script imports this file, this block is skipped — so your
functions can be reused without triggering a scan automatically.
"""
if __name__ == "__main__":
    main()


# # TCP-Paket erstellen
# tcp_packet = IP(dst=target_ip)/TCP(dport=(start_port,end_port), flags="S")
#
# # Portscan durchführen
# answered, unanswered = sr(tcp_packet, timeout=1)
#
# # Ausgabe der Ergebnisse
# for packet in answered:
#     if packet[1].haslayer(TCP) and packet[1][TCP].flags == "SA":
#         print("Port", packet[1][TCP].sport, "is open.")
#
