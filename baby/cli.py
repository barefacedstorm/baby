#!/usr/bin/env python
"""
Command-line interface for the baby DPI tool.
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime

from baby.packet_inspector import PacketInspector
from baby.ips import IPSEngine, IPSRule


def setup_logger(level=logging.INFO):
    """Set up logging configuration."""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )


def main():
    """Main entry point for the CLI."""
    # Create a description with more information
    description = '''
Baby Deep Packet Inspection Tool - A lightweight network traffic analysis tool

This tool helps you capture and analyze network traffic, detect protocols,
and identify potential security threats using a simple intrusion prevention system.
'''

    # Create an epilog with usage examples
    epilog = '''
Examples:
  # Capture 100 packets from interface en0
  baby capture -i en0 -c 100

  # Capture packets continuously and save to a directory
  baby capture -i en0 --continuous -o /path/to/output

  # Read packets from a PCAP file
  baby capture -f capture.pcap

  # Run IPS engine on interface en0
  baby ips -i en0

  # Run IPS engine with verbose output
  baby ips -i en0 -v
'''

    parser = argparse.ArgumentParser(
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter  # This preserves the formatting
    )

    # Add subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Capture command with detailed help
    capture_parser = subparsers.add_parser(
        'capture',
        help='Capture and analyze packets',
        description='''
Capture and analyze network packets from a network interface or PCAP file.
This command allows you to monitor live traffic, save captured packets to PCAP files,
and perform basic protocol detection and statistics.
''',
        epilog='''
Examples:
  # Capture packets from Wi-Fi interface
  baby capture -i en0

  # Capture 50 packets with verbose output
  baby capture -i en0 -c 50 -v

  # Continuous capture, saving to PCAP files
  baby capture -i en0 --continuous -o /path/to/save
''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    capture_parser.add_argument('-i', '--interface',
                                help='Network interface to capture from (e.g., en0 for Wi-Fi on macOS)')
    capture_parser.add_argument('-f', '--file', help='PCAP file to read packets from instead of live capture')
    capture_parser.add_argument('-c', '--count', type=int, default=100,
                                help='Number of packets to capture (0 for unlimited, default: 100)')
    capture_parser.add_argument('-v', '--verbose', action='store_true',
                                help='Enable verbose output with detailed packet information')
    capture_parser.add_argument('--continuous', action='store_true',
                                help='Run in continuous mode until manually stopped with Ctrl+C')
    capture_parser.add_argument('-o', '--output-dir',
                                help='Directory to save captured packets as PCAP files (will be created if it doesn\'t exist)')
    capture_parser.add_argument('--buffer-size', type=int, default=1000,
                                help='Number of packets to buffer before writing to disk (default: 1000)')
    capture_parser.add_argument('--rotation-interval', type=int, default=300,
                                help='Time in seconds before rotating to a new PCAP file (default: 300)')

    # IPS command with detailed help
    ips_parser = subparsers.add_parser(
        'ips',
        help='Run IPS engine',
        description='''
Run the Intrusion Prevention System (IPS) engine to monitor for suspicious network traffic.
The IPS analyzes packets in real-time, looking for patterns that match known attack signatures,
and can alert when potential security threats are detected.
''',
        epilog='''
Examples:
  # Run IPS on Wi-Fi interface
  baby ips -i en0

  # Run IPS with verbose logging
  baby ips -i en0 -v

  # Run IPS and save suspicious packets
  baby ips -i en0 -o /path/to/suspicious_packets
''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    ips_parser.add_argument('-i', '--interface', required=True,
                            help='Network interface to monitor (required)')
    ips_parser.add_argument('-r', '--rules',
                            help='Path to custom rules file (currently only built-in rules are supported)')
    ips_parser.add_argument('-c', '--count', type=int, default=0,
                            help='Number of packets to analyze (0 for infinite, default: 0)')
    ips_parser.add_argument('-v', '--verbose', action='store_true',
                            help='Enable verbose output with detailed alert information')
    ips_parser.add_argument('-o', '--output-dir',
                            help='Directory to save captured suspicious packets as PCAP files')
    ips_parser.add_argument('--continuous', action='store_true',
                            help='Run in continuous mode until manually stopped with Ctrl+C')

    # Parse arguments
    args = parser.parse_args()

    # Set up logging
    log_level = logging.DEBUG if getattr(args, 'verbose', False) else logging.INFO
    setup_logger(log_level)
    logger = logging.getLogger('baby')

    if not args.command:
        parser.print_help()
        return

    # Execute chosen command
    if args.command == 'capture':
        run_capture(args)
    elif args.command == 'ips':
        run_ips(args)


def run_capture(args):
    """Run packet capture and analysis."""
    logger = logging.getLogger('baby.capture')

    try:
        # Initialize inspector
        if args.file:
            inspector = PacketInspector(pcap_file=args.file)
            logger.info(f"Reading packets from {args.file}")
        elif args.interface:
            inspector = PacketInspector(interface=args.interface)
            logger.info(f"Capturing from interface {args.interface}")
        else:
            logger.error("Either --interface or --file must be specified")
            return 1

        # Set up PCAP output directory if specified
        if args.output_dir:
            if not os.path.exists(args.output_dir):
                os.makedirs(args.output_dir, exist_ok=True)
                logger.info(f"Created output directory: {args.output_dir}")

            inspector.set_pcap_directory(
                args.output_dir,
                buffer_size=args.buffer_size,
                rotation_interval=args.rotation_interval
            )

        # Add some basic protocol detection rules
        inspector.add_rule("http", lambda pkt: "HTTP" in str(pkt) or "GET" in str(pkt) or "POST" in str(pkt))
        inspector.add_rule("dns", lambda pkt: "DNS" in str(pkt) or "port 53" in str(pkt).lower())
        inspector.add_rule("ssh", lambda pkt: "SSH" in str(pkt) or "port 22" in str(pkt).lower())
        inspector.add_rule("tls", lambda pkt: "TLS" in str(pkt) or "port 443" in str(pkt).lower())

        # Start capture
        count = 0 if args.continuous else args.count
        logger.info(
            f"Starting packet analysis ({'continuous mode' if args.continuous else f'capturing {count} packets'})...")

        start_time = time.time()
        results = inspector.start(count=count, continuous=args.continuous)
        duration = time.time() - start_time

        # Print results
        logger.info(f"Analysis completed in {duration:.2f} seconds")
        logger.info("Protocol distribution:")
        for protocol, count in results.items():
            logger.info(f"  {protocol}: {count} packets")

        stats = inspector.get_statistics()
        if stats['total_packets'] > 0:
            logger.info(f"Total packets analyzed: {stats['total_packets']}")
        else:
            logger.warning("No packets were captured or analyzed")

    except KeyboardInterrupt:
        logger.info("Capture stopped by user")
    except Exception as e:
        logger.exception(f"Error during packet capture: {e}")
        return 1

    return 0


def run_ips(args):
    """Run IPS engine."""
    logger = logging.getLogger('baby.ips')

    try:
        # Initialize IPS engine with a packet inspector
        inspector = PacketInspector(interface=args.interface)
        ips = IPSEngine(inspector)

        # Add some basic IPS rules
        ips.add_rule(IPSRule(
            name="ssh_scan",
            detection_func=lambda pkt: "SSH" in str(pkt) and "port 22" in str(pkt).lower(),
            action="alert",
            severity=3,
            description="Potential SSH scan detected"
        ))

        ips.add_rule(IPSRule(
            name="http_exploit",
            detection_func=lambda pkt: "HTTP" in str(pkt) and any(x in str(pkt).lower() for x in [
                "union select", "exec(", "eval(", "../", "..\\", "/etc/passwd"
            ]),
            action="drop",
            severity=5,
            description="Potential HTTP exploitation attempt"
        ))

        # Start IPS engine
        logger.info(f"Starting IPS engine on interface {args.interface}...")
        logger.info("Press Ctrl+C to stop")

        # This will start the packet inspector which will trigger IPS rules
        inspector.start(count=args.count)

    except KeyboardInterrupt:
        logger.info("IPS engine stopped by user")

        # Print alerts
        alerts = ips.get_alerts()
        logger.info(f"Detected {len(alerts)} alerts:")
        for alert in alerts:
            logger.info(
                f"  {alert['timestamp']} - {alert['rule']} - Severity: {alert['severity']} - {alert['src_ip']} -> {alert['dst_ip']}")
    except Exception as e:
        logger.exception(f"Error in IPS engine: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
