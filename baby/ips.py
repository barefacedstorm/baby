"""
Intrusion Prevention System functionality for the baby package.
"""

import logging
from typing import Callable, Dict, List, Optional, Set

from .packet_inspector import PacketInspector

logger = logging.getLogger(__name__)

class IPSRule:
    """Represents a rule for the IPS engine."""

    def __init__(self, name: str, detection_func: Callable, action: str = "alert",
                 severity: int = 1, description: str = ""):
        """
        Initialize an IPS rule.

        Args:
            name: Rule name
            detection_func: Detection function that takes a packet and returns boolean
            action: Action to take ("alert", "drop", "log")
            severity: Severity level (1-5)
            description: Rule description
        """
        self.name = name
        self.detection_func = detection_func
        self.action = action
        self.severity = severity
        self.description = description

    def __str__(self):
        return f"IPSRule({self.name}, action={self.action}, severity={self.severity})"


class IPSEngine:
    """
    Engine for intrusion prevention system functionality.
    """

    def __init__(self, inspector: Optional[PacketInspector] = None):
        """
        Initialize the IPS engine.

        Args:
            inspector: PacketInspector instance to use
        """
        self.inspector = inspector or PacketInspector()
        self.rules: Dict[str, IPSRule] = {}
        self.alerts: List[Dict] = []
        self.blocked_ips: Set[str] = set()

    def add_rule(self, rule: IPSRule):
        """
        Add a rule to the IPS engine.

        Args:
            rule: IPSRule instance
        """
        self.rules[rule.name] = rule

        # Also add to the inspector
        self.inspector.add_rule(
            rule.name,
            lambda pkt: self._handle_detection(rule, pkt)
        )

        logger.info(f"Added IPS rule: {rule.name}")

    def _handle_detection(self, rule: IPSRule, packet) -> bool:
        """
        Handle rule detection and perform the appropriate action.

        Args:
            rule: The triggered rule
            packet: The packet that triggered the rule

        Returns:
            True if rule detected, False otherwise
        """
        try:
            if rule.detection_func(packet):
                # Create alert
                alert = {
                    "rule": rule.name,
                    "timestamp": getattr(packet, "time", 0),
                    "src_ip": getattr(packet, "src", "unknown"),
                    "dst_ip": getattr(packet, "dst", "unknown"),
                    "severity": rule.severity,
                    "action": rule.action
                }

                self.alerts.append(alert)

                # Perform action
                if rule.action == "drop":
                    src_ip = getattr(packet, "src", None)
                    if src_ip:
                        self.blocked_ips.add(src_ip)
                        logger.warning(f"Blocking IP {src_ip} due to rule {rule.name}")

                logger.warning(f"IPS Alert: {rule.name} - {rule.description}")
                return True
        except Exception as e:
            logger.error(f"Error in rule {rule.name}: {e}")

        return False

    def get_alerts(self, min_severity: int = 0):
        """
        Get all alerts, optionally filtered by severity.

        Args:
            min_severity: Minimum severity level to include

        Returns:
            List of alerts
        """
        if min_severity > 0:
            return [a for a in self.alerts if a["severity"] >= min_severity]
        return self.alerts

    def is_ip_blocked(self, ip: str) -> bool:
        """
        Check if an IP is blocked.

        Args:
            ip: IP address to check

        Returns:
            True if the IP is blocked, False otherwise
        """
        return ip in self.blocked_ips
