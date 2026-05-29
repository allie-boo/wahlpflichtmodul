# ----------------- <rules> ------------------
#function names: snake_case
#variable names: camelCase


# ----------------- </rules> ------------------


# ----------------- <import> -----------------
from scapy.all import IP, TCP, sr1
import argparse
import random
import sys
import time

# ----------------- </import> -----------------


# ----------------- <functions> -----------------

# TODO: Function SCANNER --type SYN
#target ip (string), port (list), timeout (float, default= 1.0), sleep_timer (float, random number between 2.0-30.0 or user input)
def scan_syn(
        target_ip: str,
        ports: list[int],
        sleep_timer: float,
        timeout: float = 1.0 ) -> tuple[list[int], list[int]]:

    open_ports: list[int] = []
    other_ports: list[int] = []

    for port in ports:
        tcp_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

        #Send and wait for response
        resp = sr1(tcp_packet, timeout=timeout, verbose=False)

        if resp is None:
            # no response → filtered / dropped / host down
            other_ports.append(port)
        elif resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags == 0x12:  # SYN/ACK -> acknolagement ist there -> Port open
                open_ports.append(port)
            else:
                # RST/ACK or other flags → not open
                other_ports.append(port)
        else:
            other_ports.append(port)

        time.sleep(sleep_timer)

    return open_ports, other_ports




# TODO: TCP Connect SCAN --type TCP

# TODO: UDP SCAN --type UDP

# TODO: Output to JSON

# TODO: Ping ICMP Packages

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
def run_scan(target: str, ports: list, type: str, sleep_time: float) -> None:
    """
    function takes target IP as STRING, ports as LIST, type as STRING, sleep_time as FLOAT
    """

    # --> dispatch to scan function
    match type:
        case "SYN":
            scan_syn(target, ports, sleep_time)
        case "TCP":
            scan_tcp(target, ports, sleep_time)
        case "UDP":
            scan_udp(target, ports, sleep_time)



    pass

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
    parser.add_argument("-s", "--sleep", default=random.randint(2, 30) , type=float, help="Sleep time in seconds (default: RANDOM range: 2-)")

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
        run_scan(target, ports, args.type, args.sleep)

# ----------------- </MAIN> -----------------

"""
Only runs when YOU execute this file directly (python3 scanner.py).
If another script imports this file, this block is skipped — so your
functions can be reused without triggering a scan automatically.
"""
if __name__ == "__main__":
    main()

#
# # Zielsystem definieren
# target_ip = "91.99.171.164"
#
# # Portbereich definieren
# start_port = 1
# end_port = 1000
#
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
