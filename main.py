"""Mini Packet Analyzer - command-line entry point."""

import argparse
import sys

from capture import create_socket, capture_packets, close_socket
from parsers import parse_packet
from display import print_summary, print_details
from filters import filter_packets

FILTER_KEYS = ("proto", "ip", "src_ip", "dst_ip", "port", "src_port", "dst_port")

MENU_HELP = """
Commands:
  s                 show packet summary
  <n> | d <n>       show details of packet number n
  f key=value ...   filter, e.g.  f proto=tcp port=443   f ip=192.168.1.0/24
                    keys: proto, ip, src_ip, dst_ip, port, src_port, dst_port
  c                 clear filters
  h                 help
  q                 quit"""


def positive_int(value):
    """argparse type: an integer of at least 1."""
    if not value.isdigit() or int(value) < 1:
        raise argparse.ArgumentTypeError(f"must be a positive number, got '{value}'")
    return int(value)


def build_arg_parser():
    """Define CLI options: packet count and filters."""
    parser = argparse.ArgumentParser(
        description="Mini Packet Analyzer: capture IPv4 packets and decode their IP, TCP and UDP headers. "
                    "Must be run as Administrator.")
    parser.add_argument("-c", "--count", type=positive_int, default=None,
                        help="number of packets to capture (default: until Ctrl+C)")

    filters = parser.add_argument_group("filters")
    filters.add_argument("--proto", choices=["tcp", "udp"], type=str.lower,
                         help="show only TCP or UDP packets")
    filters.add_argument("--ip", help="source or destination IP (a subnet like 192.168.1.0/24 also works)")
    filters.add_argument("--src-ip", help="source IP or subnet")
    filters.add_argument("--dst-ip", help="destination IP or subnet")
    filters.add_argument("--port", type=int, help="source or destination port")
    filters.add_argument("--src-port", type=int, help="source port")
    filters.add_argument("--dst-port", type=int, help="destination port")
    return parser


def interactive_menu(all_packets, current=None):
    """Let the user view the summary, apply filters and inspect a packet by number."""
    if current is None:
        current = all_packets
    print_summary(current)
    print(MENU_HELP)

    while True:
        try:
            line = input("\nanalyzer> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break
        if not line:
            continue

        cmd, *rest = line.split()
        cmd = cmd.lower()

        if cmd in ("q", "quit", "exit"):
            break
        elif cmd in ("h", "help"):
            print(MENU_HELP)
        elif cmd in ("s", "summary"):
            print_summary(current)
        elif cmd in ("c", "clear"):
            current = all_packets
            print(f"Filters cleared: {len(current)} packets")
            print_summary(current)
        elif cmd in ("f", "filter"):
            try:
                current = filter_packets(all_packets, **parse_filter_args(rest))
            except ValueError as e:
                print(f"Invalid filter: {e}")
                continue
            print(f"{len(current)} of {len(all_packets)} packets match")
            print_summary(current)
        elif cmd in ("d", "detail") or cmd.isdigit():
            num_text = cmd if cmd.isdigit() else (rest[0] if rest else "")
            if not num_text.isdigit():
                print("Usage: d <packet number>")
                continue
            packet = next((p for p in all_packets if p["num"] == int(num_text)), None)
            if packet is None:
                print(f"No packet #{num_text}")
            else:
                print_details(packet)
        else:
            print(f"Unknown command '{cmd}'. Type h for help.")


def parse_filter_args(tokens):
    """Turn ['proto=tcp', 'port=443'] into keyword arguments for filter_packets."""
    kwargs = {}
    for token in tokens:
        key, sep, value = token.partition("=")
        key = key.lower().replace("-", "_")
        if not sep or not value:
            raise ValueError(f"'{token}' should look like key=value")
        if key not in FILTER_KEYS:
            raise ValueError(f"unknown filter '{key}' (use: {', '.join(FILTER_KEYS)})")
        if key == "proto" and value.lower() not in ("tcp", "udp"):
            raise ValueError("proto must be tcp or udp")
        kwargs[key] = value
    return kwargs


def main():
    args = build_arg_parser().parse_args()
    cli_filters = {key: getattr(args, key) for key in FILTER_KEYS}

    try:
        filter_packets([], **cli_filters)
    except ValueError as e:
        print(f"Invalid filter: {e}")
        sys.exit(1)

    try:
        sock = create_socket()
    except PermissionError:
        print("Error: must be run as Administrator/root to capture packets")
        sys.exit(1)
    except OSError as e:
        print(f"Error creating socket: {e}")
        sys.exit(1)

    limit = f"{args.count} packets" if args.count else "no limit"
    print(f"Capturing packets on {sock.getsockname()[0]}... (Ctrl+C to stop, {limit})")
    try:
        packets = capture_packets(sock, count=args.count)
    except OSError as e:
        print(f"Error capturing packets: {e}")
        sys.exit(1)
    finally:
        close_socket(sock)
    print(f"Captured {len(packets)} packets")

    for p in packets:
        try:
            p["parsed"] = parse_packet(p["raw"])
        except ValueError:
            p["parsed"] = None
    parsed = [p for p in packets if p["parsed"] is not None]
    if len(parsed) < len(packets):
        print(f"Skipped {len(packets) - len(parsed)} non-IPv4/malformed packets")

    if not parsed:
        print("No packets captured.")
        return

    current = filter_packets(parsed, **cli_filters)
    if any(v is not None for v in cli_filters.values()):
        print(f"{len(current)} of {len(parsed)} packets match the command-line filters")

    interactive_menu(parsed, current)


if __name__ == "__main__":
    main()

