"""Filtering captured packets by protocol, IP address and port."""

import ipaddress


def _to_network(value):
    return ipaddress.ip_network(value, strict=False) if value is not None else None


def _to_port(value):
    return int(value) if value is not None else None


def filter_packets(packets, proto=None, ip=None, src_ip=None, dst_ip=None,
                   port=None, src_port=None, dst_port=None):
    """Return the packets that match every filter that was given."""
    ip, src_ip, dst_ip = _to_network(ip), _to_network(src_ip), _to_network(dst_ip)
    port, src_port, dst_port = _to_port(port), _to_port(src_port), _to_port(dst_port)
    port_filter = port is not None or src_port is not None or dst_port is not None

    result = []
    for p in packets:
        parsed = p.get("parsed")
        if not parsed:
            continue
        if proto is not None and parsed["protocol"].lower() != proto.lower():
            continue

        pkt_src = ipaddress.ip_address(parsed["ip"]["src_ip"])
        pkt_dst = ipaddress.ip_address(parsed["ip"]["dst_ip"])
        if ip is not None and pkt_src not in ip and pkt_dst not in ip:
            continue
        if src_ip is not None and pkt_src not in src_ip:
            continue
        if dst_ip is not None and pkt_dst not in dst_ip:
            continue

        transport = parsed["transport"]
        if port_filter and transport is None:
            continue
        if port is not None and port not in (transport["src_port"], transport["dst_port"]):
            continue
        if src_port is not None and src_port != transport["src_port"]:
            continue
        if dst_port is not None and dst_port != transport["dst_port"]:
            continue

        result.append(p)
    return result
