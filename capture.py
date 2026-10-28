"""Raw socket setup and packet capture loop."""

import socket
import sys
import time
from datetime import datetime


def create_socket():
    """Create a raw socket that receives all IP packets on the host interface."""
    pass


def capture_packets(sock, count=None):
    """Capture packets; return a list of dicts with num, timestamp, raw bytes and length."""
    pass


def close_socket(sock):
    """Disable promiscuous mode (Windows) and close the socket."""
    pass
