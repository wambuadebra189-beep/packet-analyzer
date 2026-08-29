# Custom TCP/IP Packet Analyzer

A command-line network packet analyzer built in Python using [Scapy](https://scapy.net/). It captures live network traffic and breaks it down by protocol (TCP, UDP, ICMP), showing ports, flags, sequence numbers, and payload previews in real time. Captures can also be exported to `.pcap` format for further analysis in tools like Wireshark.

## Features

- Live packet capture on any local network interface
- Parses IP, TCP, UDP, and ICMP layers
- Displays source/destination IPs, ports, TCP flags, sequence/ack numbers
- Shows a preview of packet payload data
- Custom capture filters using standard BPF syntax (same as tcpdump)
- Limit capture to a fixed number of packets, or run continuously until stopped
- End-of-capture summary showing protocol breakdown
- Export captured packets to a `.pcap` file for use in Wireshark or similar tools

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/) (`pip install scapy`)
- **Windows only:** [Npcap](https://npcap.com/) must be installed, with "WinPcap API-compatible Mode" enabled during setup
- Administrator/root privileges (packet capture requires elevated access)

## Installation

```bash
git clone https://github.com/wambuadebra189-beep/packet-analyzer.git
cd packet-analyzer
pip install scapy
```

## Usage

Run with default settings (captures on the `Wi-Fi` interface, no filter, runs until stopped):

```bash
python3 packet_analyzer.py
```

Press `Ctrl+C` to stop capturing — a summary will be printed automatically.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--iface` | Network interface to capture on | `Wi-Fi` |
| `-f`, `--filter` | BPF filter string (e.g. `"tcp port 443"`) | `ip` |
| `-c`, `--count` | Number of packets to capture (`0` = infinite) | `0` |
| `-o`, `--output` | Save captured packets to a `.pcap` file | *(none)* |

### Examples

Capture 10 packets on the default interface:

```bash
python3 packet_analyzer.py -c 10
```

Capture only HTTPS traffic and save it to a file:

```bash
python3 packet_analyzer.py -f "tcp port 443" -c 20 -o https_capture.pcap
```

Capture on a specific interface:

```bash
python3 packet_analyzer.py -i "Ethernet"
```

## Sample Output

```
Starting capture on iface=Wi-Fi filter='tcp port 443'
Press Ctrl+C to stop.

[11:31:09.329] 192.168.88.247 -> 2.17.169.250 | TTL=128 | Len=52
  TCP  sport=65251 dport=443 seq=3748193857 ack=0 flags=S
[11:31:09.357] 2.17.169.250 -> 192.168.88.247 | TTL=1 | Len=52
  TCP  sport=443 dport=65251 seq=2297493204 ack=3748193858 flags=SA
[11:31:09.359] 192.168.88.247 -> 2.17.169.250 | TTL=128 | Len=40
  TCP  sport=65251 dport=443 seq=3748193858 ack=2297493205 flags=A

--- Capture Summary ---
 TOTAL: 3
   TCP: 3
   UDP: 0
  ICMP: 0
 OTHER: 0
```

That sequence above is a complete TCP three-way handshake: `SYN` → `SYN-ACK` → `ACK`.

## Notes

- Encrypted traffic (e.g. HTTPS/TLS) will show payload data as unreadable bytes — this is expected and confirms the connection is properly encrypted, not a bug in the tool.
- Running without administrator/root privileges will typically fail silently or raise a permissions error, since raw packet capture requires elevated access.

## License

MIT
