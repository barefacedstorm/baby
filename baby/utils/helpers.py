"""
Helper functions for the baby package.
"""

import socket
import struct
from typing import Dict, List, Tuple


def ip_to_int(ip_address: str) -> int:
    """
    Convert an IP address to its integer representation.

    Args:
        ip_address: IP address string

    Returns:
        Integer representation of the IP
    """
    return struct.unpack("!I", socket.inet_aton(ip_address))[0]


def int_to_ip(ip_int: int) -> str:
    """
    Convert an integer to its IP address representation.

    Args:
        ip_int: Integer representation of an IP

    Returns:
        IP address string
    """
    return socket.inet_ntoa(struct.pack("!I", ip_int))


def is_ip_in_network(ip: str, network: str) -> bool:
    """
    Check if an IP is in the given network.

    Args:
        ip: IP address to check
        network: Network in CIDR notation (e.g., "192.168.0.0/24")

    Returns:
        True if the IP is in the network, False otherwise
    """
    # Split network address and prefix
    net_addr, prefix = network.split('/')
    prefix = int(prefix)

    # Convert to integers
    ip_int = ip_to_int(ip)
    net_int = ip_to_int(net_addr)

    # Create mask based on prefix
    mask = (0xffffffff << (32 - prefix)) & 0xffffffff

    return (ip_int & mask) == (net_int & mask)


def extract_http_info(packet_bytes: bytes) -> Dict:
    """
    Extract HTTP information from packet bytes.

    Args:
        packet_bytes: Raw packet data

    Returns:
        Dictionary with HTTP information
    """
    try:
        # Very basic HTTP parsing - in a real implementation you'd use a proper parser
        data = packet_bytes.decode('utf-8', errors='ignore')
        lines = data.split('\r\n')

        result = {"headers": {}}

        # Parse first line (request or response)
        if lines and lines[0]:
            parts = lines[0].split(' ')
            if len(parts) >= 3 and parts[0].startswith('HTTP'):
                # Response
                result["type"] = "response"
                result["version"] = parts[0]
                result["status_code"] = parts[1]
                result["status_message"] = ' '.join(parts[2:])
            elif len(parts) >= 3:
                # Request
                result["type"] = "request"
                result["method"] = parts[0]
                result["path"] = parts[1]
                result["version"] = parts[2]

        # Parse headers
        for i in range(1, len(lines)):
            line = lines[i]
            if not line:
                break

            if ': ' in line:
                key, value = line.split(': ', 1)
                result["headers"][key.lower()] = value

        return result
    except Exception:
        return {"error": "Failed to parse HTTP data"}


def common_ports() -> Dict[int, str]:
    """Return a dictionary of common port numbers and their services."""
    return {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
