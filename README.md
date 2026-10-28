# Mini Packet Analyzer

A command-line packet analyzer that captures IPv4 packets and decodes their IP, TCP and UDP headers. All header parsing is implemented manually with `struct`; no packet-decoding libraries (Scapy, PyShark, etc.) are used.

## Requirements
- Windows, Python 3.8+ (standard library only)
- Must be run from an **Administrator** terminal (raw sockets require it)

## Usage
Open an Administrator terminal and `cd` to the folder where the submission zip file has been extracted:
```
cd "path\to\extracted\folder"
```
Then run:
```
python main.py [-c COUNT] [--proto {tcp,udp}] [--ip IP] [--src-ip IP] [--dst-ip IP]
               [--port PORT] [--src-port PORT] [--dst-port PORT]
```
Without `-c`, capture runs until Ctrl+C. IP filters also accept subnets (e.g. `192.168.1.0/24`).

After capture, a summary table is shown (number, time, source/destination IP, protocol, ports, length) and an interactive prompt opens:

| Command | Action |
|---|---|
| `<n>` or `d <n>` | Show IP header, TCP/UDP header and payload of packet `n` |
| `f key=value ...` | Filter, e.g. `f proto=tcp port=443` (keys: `proto`, `ip`, `src_ip`, `dst_ip`, `port`, `src_port`, `dst_port`) |
| `c` | Clear filters |
| `s` | Show summary |
| `q` | Quit |

## Files
| File | Purpose |
|---|---|
| `main.py` | CLI arguments and interactive menu |
| `capture.py` | Raw socket setup and capture loop (number, timestamp, raw bytes, size) |
| `parsers.py` | IPv4, TCP and UDP header parsing |
| `filters.py` | Filtering by protocol, IP and port |
| `display.py` | Summary table, detailed view, hex/text payload |

## How fields are extracted from the raw packet
The socket (`AF_INET`, `SOCK_RAW`, with `SIO_RCVALL` enabled) returns each packet as `bytes` starting at the IP header. All multi-byte fields are big-endian, so every `struct` format starts with `!` (`B` = 1 byte, `H` = 2 bytes, `L` = 4 bytes, `4s` = 4 raw bytes).

**IPv4** — `struct.unpack('!BBHHHBBH4s4s', data[:20])`
- Byte 0 holds two 4-bit fields: version = `byte0 >> 4`, header length = `(byte0 & 0x0F) * 4` bytes.
- Bytes 2–3 total length, byte 8 TTL, byte 9 protocol, bytes 10–11 checksum, bytes 12–15 / 16–19 source / destination IP (converted with `socket.inet_ntoa`).
- The transport segment is `data[header_length:total_length]`, which skips IP options and drops trailing padding.
- The protocol field selects the next parser: `6` → TCP, `17` → UDP; other protocols are shown without a transport header.

**TCP** — `struct.unpack('!HHLLHHHH', segment[:20])`
- Source/destination ports, sequence and acknowledgment numbers, window and checksum are read directly.
- Bytes 12–13 pack the data offset and flags: header length = `(value >> 12) * 4`, flags = `value & 0x1FF`, with each bit mapped to a name (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS).
- Payload = `segment[header_length:]`, which skips TCP options.

**UDP** — `struct.unpack('!HHHH', segment[:8])`
- Source port, destination port, length (header + data) and checksum.
- Payload = `segment[8:length]`.

Packets without application data show a payload length of 0 and "No payload". Non-IPv4 or truncated packets are skipped.

## AI Disclosure
AI was used for debugging, making checklists, autocomplete and writing this README.

Prompts used:
- "make a plan for this assignment. keep it brief"
- "tell me the input format for the functions in parsers.py and I will start coding the functions"
- "whats the exact format of the raw data, I need to understand how to interpret it"
- "I want to write code myself. just explain the functionality and give me pointers and hints"
- "check the code"
- "fix the bugs"
- "make a checklist for main.py but dont write code"
- "make the readme. keep it concise and only write stuff that is required according to the assignment"
