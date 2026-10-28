"""Manual IPv4, TCP and UDP header parsing using struct."""

import struct
import socket

IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

TCP_FLAGS = {
    0x001: "FIN",
    0x002: "SYN",
    0x004: "RST",
    0x008: "PSH",
    0x010: "ACK",
    0x020: "URG",
    0x040: "ECE",
    0x080: "CWR",
    0x100: "NS",
}


def parse_ipv4(data):
    """Parse the IPv4 header; return a dict of fields and the remaining bytes."""
    if len(data) < 20:
        raise ValueError("packet too short for an IPv4 header")

    (ver_ihl, tos, total_length, ident, flags_frag,
     ttl, protocol, checksum, src, dst) = struct.unpack('!BBHHHBBH4s4s', data[:20])

    version = ver_ihl >> 4                 
    header_length = (ver_ihl & 0x0F) * 4
    if version != 4:
        raise ValueError(f"not an IPv4 packet (version {version})")

    ip = {
        "version": version,
        "header_length": header_length,
        "total_length": total_length,
        "ttl": ttl,
        "protocol": protocol,
        "protocol_name": IP_PROTOCOLS.get(protocol, str(protocol)),
        "checksum": checksum,
        "src_ip": socket.inet_ntoa(src),
        "dst_ip": socket.inet_ntoa(dst),
    }

    rest = data[header_length:total_length]
    return ip, rest


def parse_tcp(data):
    """Parse the TCP header; return a dict of fields and the payload."""
    if len(data) < 20:
        raise ValueError("segment too short for a TCP header")

    (src_port, dst_port, seq, ack, offset_flags,
     window, checksum, urgent) = struct.unpack('!HHLLHHHH', data[:20])

    header_length = (offset_flags >> 12) * 4
    flag_bits = offset_flags & 0x1FF
    flags = [name for bit, name in TCP_FLAGS.items() if flag_bits & bit]

    payload = data[header_length:]

    tcp = {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "header_length": header_length,
        "flags": flags,
        "window": window,
        "checksum": checksum,
        "payload_length": len(payload),
    }
    return tcp, payload


def parse_udp(data):
    """Parse the UDP header; return a dict of fields and the payload."""
    if len(data) < 8:
        raise ValueError("datagram too short for a UDP header")

    src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])

    payload = data[8:length]

    udp = {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum,
        "payload_length": len(payload),
    }
    return udp, payload


def parse_packet(raw):
    """Parse IP, then dispatch to TCP/UDP based on the protocol field."""
    ip, rest = parse_ipv4(raw)         

    if ip["protocol"] == 6:
        transport, payload = parse_tcp(rest)
        proto_name = "TCP"
    elif ip["protocol"] == 17:
        transport, payload = parse_udp(rest)
        proto_name = "UDP"
    else:                               
        transport, payload = None, rest
        proto_name = IP_PROTOCOLS.get(ip["protocol"], str(ip["protocol"]))

    return {
        "ip": ip,
        "protocol": proto_name,
        "transport": transport,         
        "payload": payload,              
    }
    