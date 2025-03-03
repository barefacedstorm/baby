"""
Test script for baby DPI package.
"""

import time
import logging
from baby import PacketInspector, IPSEngine
from baby.ips import IPSRule

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_packet_inspector():
    """Test basic packet inspection functionality."""
    print("\n=== Testing Packet Inspector ===")

    # Choose a network interface (e.g., en0, eth0, wlan0, etc.)
    # You can find your interface with:
    # - On macOS/Linux: ifconfig or ip addr
    # - On Windows: ipconfig
    interface = "en0"  # Change this to your network interface

    # Create a packet inspector
    inspector = PacketInspector(interface=interface)

    # Add some protocol detection rules
    inspector.add_rule("http", lambda pkt: "HTTP" in str(pkt) or "GET" in str(pkt) or "POST" in str(pkt))
    inspector.add_rule("dns", lambda pkt: "DNS" in str(pkt) or "port 53" in str(pkt).lower())
    inspector.add_rule("ssh", lambda pkt: "SSH" in str(pkt) or "port 22" in str(pkt).lower())
    inspector.add_rule("tls", lambda pkt: "TLS" in str(pkt) or "port 443" in str(pkt).lower())

    # Capture packets (30 packets)
    print(f"Capturing 30 packets from {interface}...")
    print("(Generate some network traffic now - try browsing a website)")
    results = inspector.start(count=30)

    # Print results
    print("\nResults:")
    for protocol, count in results.items():
        print(f"  {protocol}: {count} packets")

    stats = inspector.get_statistics()
    print(f"\nTotal packets analyzed: {stats['total_packets']}")

def test_ips_engine():
    """Test IPS engine functionality."""
    print("\n=== Testing IPS Engine ===")

    # Choose a network interface
    interface = "en0"  # Change this to your network interface

    # Create a packet inspector
    inspector = PacketInspector(interface=interface)

    # Create an IPS engine
    ips = IPSEngine(inspector)

    # Add some IPS rules
    ips.add_rule(IPSRule(
        name="dns_traffic",
        detection_func=lambda pkt: "DNS" in str(pkt),
        action="alert",
        severity=1,
        description="DNS traffic detected (this is just a test rule)"
    ))

    ips.add_rule(IPSRule(
        name="http_traffic",
        detection_func=lambda pkt: "HTTP" in str(pkt) or "GET" in str(pkt),
        action="alert",
        severity=2,
        description="HTTP traffic detected (this is just a test rule)"
    ))

    # Capture packets (15 packets)
    print(f"Running IPS engine on {interface} for 15 packets...")
    print("(Generate some network traffic now - try browsing a website)")
    inspector.start(count=15)

    # Print alerts
    alerts = ips.get_alerts()
    print(f"\nDetected {len(alerts)} alerts:")
    for alert in alerts:
        print(f"  {alert['rule']} - Severity: {alert['severity']} - {alert['src_ip']} -> {alert['dst_ip']}")

if __name__ == "__main__":
    try:
        test_packet_inspector()
        test_ips_engine()
        print("\nAll tests completed successfully!")
    except KeyboardInterrupt:
        print("\nTests stopped by user")
    except Exception as e:
        print(f"\nError during tests: {e}")
