import logging
import sys
import yaml
import threading
from baseline import Baseline
from detector import Detector
from blocker import Blocker
from unbanner import Unbanner
from notifier import (
    alert_ban, alert_unban, alert_global, send_slack
)
from monitor import Monitor
from dashboard import Dashboard

# Set up logging so every component writes
# formatted messages to the terminal
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


class Notifier:
    """
    Notifier is a simple wrapper class that bundles
    all the alert functions from notifier.py into
    one object we can pass around to other components.

    Instead of passing four separate functions everywhere,
    we pass one notifier object.
    Think of it like giving someone a whole phone
    instead of reading out every contact number.
    """
    def alert_ban(self, ip, rate, mean, stddev,
                  z_score, duration):
        alert_ban(ip, rate, mean, stddev, z_score, duration)

    def alert_unban(self, ip, reason):
        alert_unban(ip, reason)

    def alert_global(self, rate, mean, stddev, z_score):
        alert_global(rate, mean, stddev, z_score)


def main():
    """
    main is the entry point function of the entire
    detector. It creates every component, connects
    them together, and starts them all running.

    Think of it like a conductor starting an orchestra
    — each musician (component) knows their part,
    the conductor just tells them when to begin.
    """
    logger.info("Starting HNG Anomaly Detection Engine")

    # Load config
    with open("/app/config.yaml", "r") as f:
        config = yaml.safe_load(f)

    whitelist = config["whitelist"]
    log_path = config["nginx"]["log_path"]

    # Create all components
    # Each one is an object created from its class
    baseline = Baseline()
    detector = Detector()
    blocker = Blocker()
    notifier = Notifier()

    # Create unbanner and pass it the blocker and notifier
    # It needs blocker to call unban()
    # It needs notifier to send Slack alerts on unban
    unbanner = Unbanner(blocker, notifier)

    # Create dashboard and pass it the components
    # it needs to display live data
    dashboard = Dashboard(blocker, detector, baseline)

    # Create monitor — the log reader
    # It needs everything because it orchestrates
    # the whole detection flow
    monitor = Monitor(
        log_path=log_path,
        baseline=baseline,
        detector=detector,
        blocker=blocker,
        notifier=notifier,
        whitelist=whitelist
    )

    # Start background components in their own threads
    # These run silently in the background
    unbanner.start()
    dashboard.start()

    # Send a startup message to Slack so we know
    # the detector is live and watching
    send_slack(
        ":white_check_mark: *HNG Anomaly Detector Started*\n"
        "Monitoring nginx logs for anomalies."
    )

    logger.info("All components started successfully")
    logger.info(f"Dashboard available on port "
                f"{config['server']['port']}")
    logger.info(f"Whitelist: {whitelist}")

    # Start the monitor — this runs in the main thread
    # and never returns while the detector is running
    # It's an infinite loop reading log lines
    try:
        monitor.start()
    except KeyboardInterrupt:
        # KeyboardInterrupt happens when you press Ctrl+C
        # We catch it here to shut down gracefully
        logger.info("Shutting down detector...")
        monitor.stop()
        unbanner.stop()
        send_slack(
            ":octagonal_sign: *HNG Anomaly Detector Stopped*"
        )
        logger.info("Shutdown complete")


# This is a Python convention
# __name__ == "__main__" is True only when this file
# is run directly — not when it's imported by another file
# So this ensures main() only runs when we start
# the program directly
if __name__ == "__main__":
    main()
