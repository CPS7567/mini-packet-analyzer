"""Summary table, detailed packet view and payload dump."""

import binascii
import string


def print_summary(packets):
    """Print one line per packet: No, Time, Src/Dst IP, Proto, Ports, Length."""
    pass


def print_details(packet):
    """Print the full IP header, TCP/UDP header and payload of a single packet."""
    pass


def format_payload(payload):
    """Return (hex_string, printable_text) for the payload bytes."""
    pass
