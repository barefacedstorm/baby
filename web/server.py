"""
Web server for the Baby DPI tool.
This file provides a Flask-based web interface for packet capture and IPS functionality.
"""

import os
import sys
import time
import threading
import json
import logging
from datetime import datetime
import netifaces
from flask import Flask, render_template, request, jsonify, send_from_directory

# Add parent directory to path to allow importing baby package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from baby.packet_inspector import PacketInspector
from baby.ips import IPSEngine, IPSRule
import scapy.all as scapy  # Added import for scapy

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('baby.web')

# Initialize Flask app
app = Flask(__name__)

# Global variables to track capture state
active_capture = None
capture_results = {}
stop_flag = False  # Added global stop flag

# Global variables to track IPS state
active_ips = None
ips_alerts = []


# Helper function to get available network interfaces
def get_available_interfaces():
    try:
        return netifaces.interfaces()
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
        return []


# Background worker for packet capture
def capture_worker(interface, count, continuous, output_dir=None, buffer_size=1000, rotation_interval=300):
    """Background worker to run packet capture."""
    global active_capture, capture_results, stop_flag

    try:
        stop_flag = False
        logger.info(f"Starting capture on {interface}, count={count}, continuous={continuous}")

        # Initialize inspector
        inspector = PacketInspector(interface=interface)
        active_capture = inspector

        # Configure output directory if specified
        if output_dir:
            inspector.set_pcap_directory(output_dir, buffer_size, rotation_interval)

        # Add protocol detection rules
        inspector.add_rule("http", lambda pkt: "HTTP" in str(pkt) or "GET" in str(pkt) or "POST" in str(pkt))
        inspector.add_rule("dns", lambda pkt: "DNS" in str(pkt) or "port 53" in str(pkt).lower())
        inspector.add_rule("ssh", lambda pkt: "SSH" in str(pkt) or "port 22" in str(pkt).lower())
        inspector.add_rule("tls", lambda pkt: "TLS" in str(pkt) or "port 443" in str(pkt).lower())
        inspector.add_rule("tcp", lambda pkt: "TCP" in str(pkt))
        inspector.add_rule("udp", lambda pkt: "UDP" in str(pkt))
        inspector.add_rule("icmp", lambda pkt: "ICMP" in str(pkt))

        # Use a loop with short timeout to allow stopping
        logger.info(f"Starting packet inspector with count={count if not continuous else 0}, continuous={continuous}")

        while not stop_flag:
            # Sniff with a short timeout
            scapy.sniff(
                iface=interface,
                prn=inspector.process_packet,
                count=10,  # Sniff in small batches
                timeout=1, # Short timeout to check stop_flag frequently
                store=0    # Don't store packets in memory
            )

            if not continuous and inspector.packet_count >= count:
                break

        logger.info(f"Capture completed with results: {inspector.detected_protocols}")
        # Store results
        capture_results = inspector.detected_protocols

    except Exception as e:
        logger.error(f"Error in capture worker: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        active_capture = None
        logger.info("Capture worker finished")


# Background worker for IPS engine
def ips_worker(interface, continuous, output_dir=None):
    """Background worker to run IPS engine."""
    global active_ips, ips_alerts

    try:
        logger.info(f"Starting IPS on {interface}, continuous={continuous}")

        # Initialize packet inspector
        inspector = PacketInspector(interface=interface)

        # Initialize IPS engine
        ips = IPSEngine(inspector)
        active_ips = ips

        # Configure output directory if specified
        if output_dir:
            inspector.set_pcap_directory(output_dir)

        # Add IPS rules
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

        ips.add_rule(IPSRule(
            name="dns_tunneling",
            detection_func=lambda pkt: "DNS" in str(pkt) and len(str(pkt)) > 300,
            action="alert",
            severity=4,
            description="Potential DNS tunneling detected"
        ))

        # Start IPS engine (which starts the packet inspector)
        count = 0 if continuous else 1000
        inspector.start(count=count)

        # IPS alerts are collected via get_alerts()
        ips_alerts = ips.get_alerts()

    except Exception as e:
        logger.error(f"Error in IPS worker: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        active_ips = None
        logger.info("IPS worker finished")


# Web routes
@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')


@app.route('/capture')
def capture_page():
    """Packet capture page."""
    interfaces = get_available_interfaces()
    return render_template('capture.html', interfaces=interfaces)


@app.route('/ips')
def ips_page():
    """IPS engine page."""
    interfaces = get_available_interfaces()
    return render_template('ips.html', interfaces=interfaces)


# Static files
@app.route('/static/<path:path>')
def serve_static(path):
    """Serve static files."""
    return send_from_directory('static', path)


# API endpoints
@app.route('/api/interfaces')
def get_interfaces():
    """API endpoint to get available network interfaces."""
    try:
        interfaces = get_available_interfaces()
        return jsonify({"interfaces": interfaces})
    except Exception as e:
        logger.error(f"Error in /api/interfaces: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/start_capture', methods=['POST'])
def start_capture():
    """API endpoint to start packet capture."""
    global active_capture, stop_flag

    if active_capture:
        return jsonify({"success": False, "message": "Capture already running"}), 400

    try:
        data = request.json
        interface = data.get('interface')
        count = int(data.get('count', 100))
        continuous = data.get('continuous', False)
        output_dir = data.get('output_dir')

        if not interface:
            return jsonify({"success": False, "message": "Interface is required"}), 400

        # Reset stop flag
        stop_flag = False

        # Start capture in a background thread
        thread = threading.Thread(
            target=capture_worker,
            args=(interface, count, continuous, output_dir),
            daemon=True
        )
        thread.start()

        return jsonify({
            "success": True,
            "message": f"Capture started on {interface}"
        })
    except Exception as e:
        logger.error(f"Error in /api/start_capture: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/stop_capture', methods=['POST'])
def stop_capture():
    """API endpoint to stop packet capture."""
    global active_capture, stop_flag

    if not active_capture:
        return jsonify({"success": False, "message": "No capture running"}), 400

    try:
        # Set stop flag to signal worker to stop
        stop_flag = True
        logger.info("Stop flag set to True, waiting for capture to stop")

        return jsonify({
            "success": True,
            "message": "Capture stopping..."
        })
    except Exception as e:
        logger.error(f"Error in /api/stop_capture: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/capture_status')
def capture_status():
    """API endpoint to get capture status."""
    global active_capture, capture_results

    is_active = active_capture is not None

    try:
        if active_capture:
            stats = active_capture.get_statistics()
            # Return current results while capture is active
            current_results = active_capture.detected_protocols
            return jsonify({
                "active": is_active,
                "packets": stats.get('total_packets', 0),
                "results": current_results
            })
        else:
            # Return final results after capture is done
            return jsonify({
                "active": False,
                "packets": sum(capture_results.values()) if capture_results else 0,
                "results": capture_results
            })
    except Exception as e:
        logger.error(f"Error in /api/capture_status: {e}")
        return jsonify({
            "active": is_active,
            "error": str(e),
            "results": {}
        })


@app.route('/api/start_ips', methods=['POST'])
def start_ips():
    """API endpoint to start IPS engine."""
    global active_ips

    if active_ips:
        return jsonify({"success": False, "message": "IPS already running"}), 400

    try:
        data = request.json
        interface = data.get('interface')
        continuous = data.get('continuous', True)
        output_dir = data.get('output_dir')

        if not interface:
            return jsonify({"success": False, "message": "Interface is required"}), 400

        # Start IPS in a background thread
        thread = threading.Thread(
            target=ips_worker,
            args=(interface, continuous, output_dir),
            daemon=True
        )
        thread.start()

        return jsonify({
            "success": True,
            "message": f"IPS started on {interface}"
        })
    except Exception as e:
        logger.error(f"Error in /api/start_ips: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/stop_ips', methods=['POST'])
def stop_ips():
    """API endpoint to stop IPS engine."""
    global active_ips

    if not active_ips:
        return jsonify({"success": False, "message": "No IPS running"}), 400

    try:
        # Similar to capture, we can't directly stop scapy.sniff
        active_ips = None

        return jsonify({
            "success": True,
            "message": "IPS stopping..."
        })
    except Exception as e:
        logger.error(f"Error in /api/stop_ips: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/ips_alerts')
def ips_alerts_endpoint():
    """API endpoint to get IPS alerts."""
    global active_ips, ips_alerts

    is_active = active_ips is not None

    try:
        if active_ips:
            # Get alerts from active IPS
            current_alerts = active_ips.get_alerts()
            return jsonify({
                "active": is_active,
                "alerts": current_alerts
            })
        else:
            # Return stored alerts after IPS is done
            return jsonify({
                "active": False,
                "alerts": ips_alerts
            })
    except Exception as e:
        logger.error(f"Error in /api/ips_alerts: {e}")
        return jsonify({
            "active": is_active,
            "error": str(e),
            "alerts": []
        })


# Main entry point
if __name__ == '__main__':
    # Get port from environment or use default
    port = int(os.environ.get('PORT', 5000))

    # Start Flask app
    logger.info(f"Starting Baby DPI web server on port {port}")
    app.run(host='0.0.0.0', port=5001, debug=True)
