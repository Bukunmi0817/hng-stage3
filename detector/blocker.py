import subprocess
import logging
import yaml
import time
from threading import Lock

# Load config
with open("/app/config.yaml", "r") as f:
    config = yaml.safe_load(f)

WHITELIST = config["whitelist"]
BAN_DURATIONS = config["blocking"]["ban_durations"]

logger = logging.getLogger(__name__)


class Blocker:
    """
    Blocker manages iptables rules for banning IPs.
    It keeps track of how many times each IP has been
    banned so it can apply the correct duration.
    """

    def __init__(self):
        # banned_ips is a dictionary that stores
        # information about currently banned IPs
        # Example:
        # {
        #   "1.2.3.4": {
        #     "banned_at": 1714000000,
        #     "duration": 600,
        #     "offense_count": 1
        #   }
        # }
        self.banned_ips = {}

        # offense_count tracks how many times each IP
        # has been banned before — determines which
        # duration from the backoff schedule to apply
        self.offense_counts = {}

        self.lock = Lock()

    def is_whitelisted(self, ip: str) -> bool:
        """
        is_whitelisted is a function that checks if an IP
        is on the whitelist. If it is, we never block it
        no matter how much traffic it sends.

        Think of it like a VIP list at a nightclub —
        these people always get in regardless.
        """
        return ip in WHITELIST

    def is_banned(self, ip: str) -> bool:
        """
        is_banned is a function that checks if an IP
        is currently in our banned_ips dictionary.
        """
        with self.lock:
            return ip in self.banned_ips

    def ban(self, ip: str, notifier=None,
            rate: float = 0, mean: float = 0,
            stddev: float = 0, z_score: float = 0):
        """
        ban is a function that:
        1. Checks the IP is not whitelisted
        2. Checks the IP is not already banned
        3. Determines the ban duration based on
           how many times this IP has offended before
        4. Adds an iptables DROP rule
        5. Records the ban details
        6. Sends a Slack alert
        7. Writes to the audit log
        """
        if self.is_whitelisted(ip):
            logger.info(f"IP {ip} is whitelisted — skipping ban")
            return

        with self.lock:
            if ip in self.banned_ips:
                logger.info(f"IP {ip} already banned")
                return

            # Get offense count for this IP
            # If we've never seen this IP before, count is 0
            count = self.offense_counts.get(ip, 0)

            # Pick the duration from the backoff schedule
            # min() makes sure we don't go past the last entry
            # Example: if count is 0, duration is BAN_DURATIONS[0] = 600
            # if count is 1, duration is BAN_DURATIONS[1] = 1800
            # if count is 5, duration is BAN_DURATIONS[-1] = -1 (permanent)
            duration_index = min(count, len(BAN_DURATIONS) - 1)
            duration = BAN_DURATIONS[duration_index]

            # Add iptables rule
            # subprocess.run is a function that runs a
            # shell command from inside Python
            # This is how we talk to the Linux firewall
            result = subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                logger.error(f"iptables failed: {result.stderr}")
                return

            # Record the ban
            self.banned_ips[ip] = {
                "banned_at": time.time(),
                "duration": duration,
                "offense_count": count + 1
            }

            # Update offense count for next time
            self.offense_counts[ip] = count + 1

            duration_str = "PERMANENT" if duration == -1 \
                else f"{duration}s"

            logger.info(
                f"[BAN] {ip} | rate={rate:.2f} | "
                f"mean={mean:.2f} | duration={duration_str}"
            )

            # Write to audit log
            self._audit_log(
                "BAN", ip,
                f"rate={rate:.2f} mean={mean:.2f} "
                f"z={z_score:.2f} duration={duration_str}"
            )

            # Send Slack alert
            if notifier:
                notifier.alert_ban(
                    ip, rate, mean, stddev, z_score, duration
                )

    def unban(self, ip: str, notifier=None, reason: str = "scheduled"):
        """
        unban is a function that removes the iptables
        DROP rule for an IP and removes it from
        our banned_ips dictionary.
        """
        with self.lock:
            if ip not in self.banned_ips:
                return

            # Remove iptables rule
            # -D means DELETE the rule
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True
            )

            del self.banned_ips[ip]

            logger.info(f"[UNBAN] {ip} | reason={reason}")

            self._audit_log("UNBAN", ip, f"reason={reason}")

            if notifier:
                notifier.alert_unban(ip, reason)

    def get_banned_ips(self) -> dict:
        """
        get_banned_ips is a function that returns a copy
        of the banned IPs dictionary.
        Used by the dashboard to display current bans.
        """
        with self.lock:
            return dict(self.banned_ips)

    def _audit_log(self, action: str, ip: str, details: str):
        """
        _audit_log is a function that writes a structured
        log entry to the audit log file.

        Format:
        [timestamp] ACTION ip | details
        """
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                  time.gmtime())
        entry = (
            f"[{timestamp}] {action} {ip} | {details}\n"
        )
        try:
            with open(config["audit"]["log_path"], "a") as f:
                f.write(entry)
        except Exception as e:
            logger.error(f"Audit log write failed: {e}")
