import requests
import yaml
import logging
from datetime import datetime

# Load config
with open("/app/config.yaml", "r") as f:
    config = yaml.safe_load(f)

WEBHOOK_URL = config["slack"]["webhook_url"]

logger = logging.getLogger(__name__)


def send_slack(message: str):
    """
    send_slack is a function that takes a message string
    and sends it to the Slack channel via webhook.
    If it fails it logs the error but does not crash the program.
    """
    try:
        response = requests.post(
            WEBHOOK_URL,
            json={"text": message},
            timeout=5
        )
        if response.status_code != 200:
            logger.error(f"Slack error: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"Slack send failed: {e}")


def alert_ban(ip: str, rate: float, mean: float, stddev: float,
              z_score: float, duration: int):
    """
    alert_ban is a function that sends a Slack notification
    when an IP is banned. It formats all the relevant details
    into a readable message.
    """
    if duration == -1:
        duration_str = "PERMANENT"
    else:
        duration_str = f"{duration} seconds"

    message = (
        f":rotating_light: *IP BANNED*\n"
        f"*IP:* `{ip}`\n"
        f"*Condition:* Anomaly detected\n"
        f"*Current Rate:* {rate:.2f} req/s\n"
        f"*Baseline Mean:* {mean:.2f} req/s\n"
        f"*Baseline Stddev:* {stddev:.2f}\n"
        f"*Z-Score:* {z_score:.2f}\n"
        f"*Ban Duration:* {duration_str}\n"
        f"*Timestamp:* {datetime.utcnow().isoformat()}Z"
    )
    send_slack(message)


def alert_unban(ip: str, reason: str):
    """
    alert_unban is a function that sends a Slack notification
    when an IP ban is lifted.
    """
    message = (
        f":white_check_mark: *IP UNBANNED*\n"
        f"*IP:* `{ip}`\n"
        f"*Reason:* {reason}\n"
        f"*Timestamp:* {datetime.utcnow().isoformat()}Z"
    )
    send_slack(message)


def alert_global(rate: float, mean: float, stddev: float, z_score: float):
    """
    alert_global is a function that sends a Slack notification
    when global traffic (from all IPs combined) is anomalous.
    We don't block in this case — just alert.
    """
    message = (
        f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
        f"*Current Global Rate:* {rate:.2f} req/s\n"
        f"*Baseline Mean:* {mean:.2f} req/s\n"
        f"*Baseline Stddev:* {stddev:.2f}\n"
        f"*Z-Score:* {z_score:.2f}\n"
        f"*Timestamp:* {datetime.utcnow().isoformat()}Z"
    )
    send_slack(message)
