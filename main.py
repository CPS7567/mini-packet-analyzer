"""Mini Packet Analyzer - command-line entry point."""

import argparse
import sys

from capture import create_socket, capture_packets, close_socket
from parsers import parse_packet
from display import print_summary, print_details
from filters import filter_packets


def build_arg_parser():
    """Define CLI options: packet count and filters."""
    pass


def interactive_menu(packets):
    """Let the user view the summary, apply filters and inspect a packet by number."""
    pass


def main():
    pass


if __name__ == "__main__":
    main()
