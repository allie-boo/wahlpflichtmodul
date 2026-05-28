from scapy.all import *

# ----------------- <functions> -----------------

# TODO: Function for user input "ip, ports, flags" - +error_handling

# TODO: Function IP-address tabel .txt

# TODO: Function port randomise

# TODO: sleep timer

# TODO: UDP SCAN

# TODO: Output to JSON

# TODO: Ping ICMP Packete

# ----------------- </functions> -----------------




# Zielsystem definieren
target_ip = "91.99.171.164"

# Portbereich definieren
start_port = 1
end_port = 1000

# TCP-Paket erstellen
tcp_packet = IP(dst=target_ip)/TCP(dport=(start_port,end_port), flags="S")

# Portscan durchführen
answered, unanswered = sr(tcp_packet, timeout=1)

# Ausgabe der Ergebnisse
for packet in answered:
    if packet[1].haslayer(TCP) and packet[1][TCP].flags == "SA":
        print("Port", packet[1][TCP].sport, "is open.")

