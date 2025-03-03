"""
Simple packet capture test to verify scapy functionality.
"""

import sys
import logging
from scapy.all import sniff

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def packet_callback(packet):
    """Process each packet"""
    logger.info(f"Captured packet: {packet.summary()}")


def main():
    """Main function"""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        return 1

    interface = sys.argv[1]
    count = 10

    logger.info(f"Starting capture on {interface} (will capture {count} packets)")

    try:
        sniff(iface=interface, prn=packet_callback, count=count, store=0)
        logger.info("Capture completed successfully")
    except KeyboardInterrupt:
        logger.info("Capture stopped by user")
    except Exception as e:
        logger.error(f"Error during capture: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
EOL

chmod + x
test_capture.py
