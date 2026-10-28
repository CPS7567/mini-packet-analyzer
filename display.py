"""Summary table, detailed packet view and payload dump."""

PAYLOAD_LIMIT = 256


def print_summary(packets):
    """Print one line per packet: No, Time, Src/Dst IP, Proto, Ports, Length."""
    print(f"{'No':>5}  {'Time':<12}  {'Source':<15}  {'Destination':<15}  "
          f"{'Proto':<5}  {'SPort':>5}  {'DPort':>5}  {'Length':>6}")
    print("-" * 85)
    for p in packets:
        parsed = p["parsed"]
        ip = parsed["ip"]
        t = parsed["transport"] or {}
        print(f"{p['num']:>5}  {p['timestamp']:<12}  {ip['src_ip']:<15}  {ip['dst_ip']:<15}  "
              f"{parsed['protocol']:<5}  {t.get('src_port', '-'):>5}  {t.get('dst_port', '-'):>5}  "
              f"{p['length']:>6}")


def _section(title):
    print(f"\n{title}")
    print("-" * 32)


def _row(label, value):
    print(f"{label + ':':<20}{value}")


def print_details(packet):
    """Print the full IP header, TCP/UDP header and payload of a single packet."""
    parsed = packet["parsed"]
    ip = parsed["ip"]
    t = parsed["transport"]

    print(f"\nPacket #{packet['num']}")
    print(f"Time: {packet['timestamp']}")
    print(f"Packet Length: {packet['length']} bytes")

    _section("IP Header")
    _row("Version", ip["version"])
    _row("Header Length", f"{ip['header_length']} bytes")
    _row("Total Length", f"{ip['total_length']} bytes")
    _row("TTL", ip["ttl"])
    _row("Protocol", f"{ip['protocol_name']} ({ip['protocol']})")
    _row("Header Checksum", f"0x{ip['checksum']:04X}")
    _row("Source IP", ip["src_ip"])
    _row("Destination IP", ip["dst_ip"])

    if parsed["protocol"] == "TCP":
        _section("TCP Header")
        _row("Source Port", t["src_port"])
        _row("Destination Port", t["dst_port"])
        _row("Sequence Number", t["seq"])
        _row("Acknowledgment", t["ack"])
        _row("Header Length", f"{t['header_length']} bytes")
        _row("Flags", ", ".join(t["flags"]) or "None")
        _row("Window Size", t["window"])
        _row("Checksum", f"0x{t['checksum']:04X}")
        _row("Payload Length", f"{t['payload_length']} bytes")
    elif parsed["protocol"] == "UDP":
        _section("UDP Header")
        _row("Source Port", t["src_port"])
        _row("Destination Port", t["dst_port"])
        _row("Length", f"{t['length']} bytes")
        _row("Checksum", f"0x{t['checksum']:04X}")
        _row("Payload Length", f"{t['payload_length']} bytes")
    else:
        print(f"\n{parsed['protocol']} transport header is not decoded.")

    _section("Payload")
    payload = parsed["payload"]
    if not payload:
        print("No payload (0 bytes)")
        return
    hex_lines, text = format_payload(payload)
    print("Hex:")
    print("\n".join(hex_lines))
    print("\nText:")
    print(text)


def format_payload(payload, limit=PAYLOAD_LIMIT):
    """Return (hex_lines, printable_text) for the first `limit` payload bytes."""
    shown = payload[:limit]

    hex_lines = [f"{i:04X}  {shown[i:i + 16].hex(' ').upper()}"
                 for i in range(0, len(shown), 16)]

    text = "".join(chr(b) if 32 <= b < 127 else "." for b in shown)
    text = "\n".join(text[i:i + 64] for i in range(0, len(text), 64))

    if len(payload) > limit:
        hex_lines.append(f"... ({len(payload) - limit} more bytes)")
        text += " ..."
    return hex_lines, text
