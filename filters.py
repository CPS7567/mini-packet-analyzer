"""Filtering captured packets by protocol, IP address and port."""

import ipaddress


def filter_packets(packets, proto=None, ip=None, src_ip=None, dst_ip=None,
                   port=None, src_port=None, dst_port=None):
    """Return the packets that match every filter that was given."""
    pass
