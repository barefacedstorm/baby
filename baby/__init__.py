"""
baby - A lightweight deep packet inspection and IPS utility.
"""

from .packet_inspector import PacketInspector
from .ips import IPSEngine

__version__ = "0.1.0"
__all__ = ["PacketInspector", "IPSEngine"]
