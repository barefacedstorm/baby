"""
Core packet inspection functionality for the baby package.
"""

import logging
import os
import time
import traceback
from datetime import datetime
from typing import Callable, Dict, List, Optional, Union

try:
    import scapy.all as scapy
except ImportError:
    raise ImportError("Scapy is required for packet inspection. Install with 'pip install scapy'")

logger = logging.getLogger(__name__)

class PacketInspector:
    """
    Class for deep packet inspection of network traffic.
    """

    def __init__(self, interface: str = None, pcap_file: str = None):
        """
        Initialize the packet inspector.

        Args:
            interface: Network interface to capture from
            pcap_file: PCAP file to read packets from
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self.rules: Dict[str, Callable] = {}
        self.detected_protocols: Dict[str, int] = {}
        self.packet_count = 0
        self.has_error = False
        self.captured_packets = []  # For storing packets when needed
        self.pcap_dir = None        # Directory to save pcaps
        self.pcap_buffer_size = 1000  # Number of packets before writing a pcap
        self.pcap_rotation_interval = 300  # 5 minutes in seconds
        self.last_rotation_time = time.time()

        if not interface and not pcap_file:
            raise ValueError("Either interface or pcap_file must be provided")

        logger.info(f"PacketInspector initialized with {'interface: ' + interface if interface else 'pcap_file: ' + pcap_file}")

    def set_pcap_directory(self, directory: str, buffer_size: int = 1000, rotation_interval: int = 300):
        """
        Set the directory for saving pcap files.

        Args:
            directory: Directory to save pcap files
            buffer_size: Number of packets to capture before writing to disk
            rotation_interval: Time in seconds before rotating to a new file
        """
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

        self.pcap_dir = directory
        self.pcap_buffer_size = buffer_size
        self.pcap_rotation_interval = rotation_interval
        self.last_rotation_time = time.time()
        logger.info(f"Will save captured packets to {directory}")
        logger.info(f"PCAP buffer size: {buffer_size}, rotation interval: {rotation_interval}s")

    def _write_pcap_file(self):
        """Write captured packets to a PCAP file and clear the buffer."""
        if not self.pcap_dir or not self.captured_packets:
            return

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = os.path.join(self.pcap_dir, f"capture_{timestamp}.pcap")

        try:
            logger.info(f"Writing {len(self.captured_packets)} packets to {filename}")
            scapy.wrpcap(filename, self.captured_packets)
            self.captured_packets = []
            self.last_rotation_time = time.time()
        except Exception as e:
            logger.error(f"Error writing PCAP file: {e}")

    def add_rule(self, name: str, detection_func: Callable):
        """
        Add a detection rule.

        Args:
            name: Name of the rule/protocol
            detection_func: Function that takes a packet and returns boolean
        """
        self.rules[name] = detection_func
        logger.debug(f"Added rule: {name}")

    def process_packet(self, packet):
        """
        Process a single packet through all rules.

        Args:
            packet: Scapy packet to analyze
        """
        try:
            self.packet_count += 1

            # Store packet if pcap_dir is set
            if self.pcap_dir:
                self.captured_packets.append(packet)

                # Check if we need to write packets to disk
                if len(self.captured_packets) >= self.pcap_buffer_size or \
                   (time.time() - self.last_rotation_time) >= self.pcap_rotation_interval:
                    self._write_pcap_file()

            # Log progress periodically
            if self.packet_count % 100 == 0:
                logger.info(f"Processed {self.packet_count} packets so far")

            # Always log at least some basic info about the first few packets
            if self.packet_count <= 5:
                try:
                    packet_summary = packet.summary() if hasattr(packet, 'summary') else str(packet)
                    logger.debug(f"Packet #{self.packet_count} summary: {packet_summary}")
                except Exception as e:
                    logger.debug(f"Could not summarize packet: {e}")

            # Apply rules
            rule_matched = False
            for rule_name, rule_func in self.rules.items():
                try:
                    result = rule_func(packet)
                    if result:
                        self.detected_protocols[rule_name] = self.detected_protocols.get(rule_name, 0) + 1
                        logger.debug(f"Packet #{self.packet_count} matched rule: {rule_name}")
                        rule_matched = True
                except Exception as e:
                    logger.warning(f"Error applying rule {rule_name}: {e}")

            # If no rule matched, count as "unknown"
            if not rule_matched:
                self.detected_protocols["unknown"] = self.detected_protocols.get("unknown", 0) + 1

        except Exception as e:
            self.has_error = True
            logger.error(f"Critical error processing packet: {e}")
            logger.error(traceback.format_exc())

    def start(self, count: int = 0, timeout: int = None, continuous: bool = False):
        """
        Start capturing and analyzing packets.

        Args:
            count: Number of packets to capture (0 for infinite)
            timeout: Timeout in seconds
            continuous: Whether to run in continuous mode (ctrl+c to stop)

        Returns:
            Dict of detected protocols and counts
        """
        try:
            if self.pcap_file:
                logger.info(f"Reading from PCAP file: {self.pcap_file}")
                packets = scapy.rdpcap(self.pcap_file)
                for packet in packets[:count if count else None]:
                    self.process_packet(packet)
            else:
                logger.info(f"Starting live capture on {self.interface}")
                if continuous:
                    logger.info("Running in continuous mode. Press Ctrl+C to stop.")
                    count = 0  # Set count to 0 for infinite capture
                else:
                    logger.info(f"Will capture {count if count else 'unlimited'} packets")

                def packet_callback(packet):
                    # Wrap in try-except to prevent callback from breaking capture
                    try:
                        self.process_packet(packet)
                    except Exception as e:
                        logger.error(f"Error in packet callback: {e}")

                try:
                    scapy.sniff(
                        iface=self.interface,
                        prn=packet_callback,
                        count=count,
                        timeout=timeout,
                        store=0  # Don't store packets in memory
                    )
                    logger.info(f"Sniffing completed normally")
                except KeyboardInterrupt:
                    logger.info("Capture stopped by user")
                    # Write any remaining packets to disk
                    if self.pcap_dir and self.captured_packets:
                        self._write_pcap_file()
                except Exception as e:
                    logger.error(f"Error during packet capture: {str(e)}")
                    logger.error(traceback.format_exc())

            # Final write of any remaining packets
            if self.pcap_dir and self.captured_packets:
                self._write_pcap_file()

            logger.info(f"Capture completed. Total packets processed: {self.packet_count}")

            return self.detected_protocols

        except Exception as e:
            logger.error(f"Critical error in capture process: {e}")
            logger.error(traceback.format_exc())
            return self.detected_protocols

    def get_statistics(self):
        """Get statistics about detected protocols."""
        return {
            "total_packets": self.packet_count,
            "protocol_distribution": self.detected_protocols,
            "had_errors": self.has_error
        }
