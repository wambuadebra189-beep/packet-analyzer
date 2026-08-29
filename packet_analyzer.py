from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import argparse

stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0}


def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        stats["total"] += 1

        print(f"\n[{timestamp}] {ip_layer.src} -> {ip_layer.dst} | TTL={ip_layer.ttl} | Len={ip_layer.len}")

        if TCP in packet:
            stats["tcp"] += 1
            tcp_layer = packet[TCP]
            print(f"  TCP  sport={tcp_layer.sport} dport={tcp_layer.dport} "
                  f"seq={tcp_layer.seq} ack={tcp_layer.ack} flags={tcp_layer.flags}")

        elif UDP in packet:
            stats["udp"] += 1
            udp_layer = packet[UDP]
            print(f"  UDP  sport={udp_layer.sport} dport={udp_layer.dport} len={udp_layer.len}")

        elif ICMP in packet:
            stats["icmp"] += 1
            icmp_layer = packet[ICMP]
            print(f"  ICMP type={icmp_layer.type} code={icmp_layer.code}")

        else:
            stats["other"] += 1

        if Raw in packet:
            payload = bytes(packet[Raw].load)
            preview = payload[:32]
            print(f"  Payload ({len(payload)} bytes): {preview}")


def print_summary():
    print("\n\n--- Capture Summary ---")
    for key, value in stats.items():
        print(f"{key.upper():>6}: {value}")


def main():
    parser = argparse.ArgumentParser(description="Custom TCP/IP Packet Analyzer")
    parser.add_argument("-i", "--iface", default="Wi-Fi", help="Network interface (default: Wi-Fi)")
    parser.add_argument("-f", "--filter", default="ip", help="BPF filter (e.g. 'tcp port 443')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    args = parser.parse_args()

    print(f"Starting capture on iface={args.iface} filter='{args.filter}'")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(iface=args.iface, filter=args.filter, prn=analyze_packet, count=args.count, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        print_summary()


if __name__ == "__main__":
    main()