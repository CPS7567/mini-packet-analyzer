"""Raw socket setup and packet capture loop."""

import socket
import sys
import time
from datetime import datetime


def create_socket():
    """Create a raw socket that receives all IP packets on the host interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    host_ip = s.getsockname()[0]
    s.close()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind((host_ip, 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    if sys.platform == "win32":
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    return sock


def capture_packets(sock, count=None):
    """Capture packets; return a list of dicts with num, timestamp, raw bytes and length."""
    packets = []
    sock.settimeout(1.0)
    try:
        start_time = time.time()
        while count is None or len(packets) < count:
            try:
                raw, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            packets.append({"num": len(packets) + 1, "timestamp": timestamp, "relative_time": time.time() - start_time, "raw": raw, "length": len(raw)})
    except KeyboardInterrupt:
        print(f"\nCapture stopped: {len(packets)} packets")
    return packets



def close_socket(sock):
    """Disable promiscuous mode (Windows) and close the socket."""
    if sys.platform == "win32":
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    sock.close()
