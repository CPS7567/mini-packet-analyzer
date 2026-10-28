"""Manual IPv4, TCP and UDP header parsing using struct."""

import struct
import socket
import ipaddress

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
    pass


def parse_tcp(data):
    """Parse the TCP header; return a dict of fields and the payload."""
    pass


def parse_udp(data):
    """Parse the UDP header; return a dict of fields and the payload."""
    pass


def parse_packet(raw):
    """Parse IP, then dispatch to TCP/UDP based on the protocol field."""
    pass


def test():
    raw = bytes.fromhex(
    "45000021" "1c464000" "40110000" "c0a8010a" "c0a80114"  # IP header (20 B)
    "d4310035" "000d0000"                                  # UDP header (8 B)
    "68656c6c6f"                                           # payload "hello"
)
    print(raw.hex())
    # packet = parse_packet(raw)
    # print(packet)
    
test()