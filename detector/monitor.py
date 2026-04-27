import json
import time
import logging
import os

logger = logging.getLogger(__name__)


class Monitor:
    """
    Monitor continuously reads the nginx access log
    line by line in real time — like tail -f in the terminal.

    Think of it like a person sitting next to a printer
    picking up every page the moment it comes out and
    passing it to the right department.
    """

    def __init__(self, log_path: str, baseline,
                 detector, blocker, notifier, whitelist):
        self.log_path = log_path
        self.baseline = baseline
        self.detector = detector
        self.blocker = blocker
        self.notifier = notifier
        self.whitelist = whitelist
        self.running = True

    def start(self):
        """
        start is a function that begins tailing the
        nginx log file from the end.

        Why from the end? Because when the detector
        starts up, the log file might already have
        millions of old lines in it. We don't want
        to process all of them — we only care about
        new requests happening right now.

        So we seek to the end of the file first,
        then start reading from there.
        """
        logger.info(f"Starting monitor on {self.log_path}")

        # Wait for the log file to exist
        # It might not exist yet if nginx just started
        while not os.path.exists(self.log_path):
            logger.info("Waiting for log file to appear...")
            time.sleep(2)

        with open(self.log_path, "r") as f:
            # seek(0, 2) moves the file cursor to the end
            # 0 means "move 0 bytes" and 2 means "from the end"
            # This skips all existing log lines
            f.seek(0, 2)
            logger.info("Log file found. Monitoring started.")

            while self.running:
                line = f.readline()

                if not line:
                    # No new line yet — wait a tiny bit
                    # and try again
                    # This is called "polling"
                    time.sleep(0.05)
                    continue

                # We got a new line — process it
                self._process_line(line.strip())

    def _process_line(self, line: str):
        """
        _process_line is a function that takes one raw
        log line, parses it from JSON into a Python
        dictionary, and passes the data to the
        baseline, detector, and blocker.

        Think of it like a translator — the log line
        comes in as raw text, this function converts
        it into structured data the other components
        can understand.
        """
        if not line:
            return

        try:
            # json.loads() is a function that converts
            # a JSON string into a Python dictionary
            # "loads" means "load from string"
            data = json.loads(line)
        except json.JSONDecodeError:
            # If the line isn't valid JSON, skip it
            logger.warning(f"Could not parse line: {line[:100]}")
            return

        # Extract the fields we care about
        ip = data.get("source_ip", "")
        status = int(data.get("status", 200))

        # Clean up the IP — sometimes X-Forwarded-For
        # contains multiple IPs separated by commas
        # like "1.2.3.4, 5.6.7.8"
        # We only want the first one — the real client
        if "," in ip:
            ip = ip.split(",")[0].strip()

        if not ip or ip == "-":
            return

        # Skip whitelisted IPs entirely
        if ip in self.whitelist:
            return

        # Tell the baseline a request came in
        self.baseline.record_request()

        # Tell the detector a request came in from this IP
        self.detector.record(ip, status)

        # Now check if this IP is anomalous
        self._check_ip(ip)

        # Also check global traffic
        self._check_global()

    def _check_ip(self, ip: str):
        """
        _check_ip is a function that checks whether
        a specific IP's current request rate is anomalous.

        It gets the IP's rate, gets the baseline values,
        checks for error surge, then asks the detector
        if it's an anomaly.

        If yes — and the IP isn't already banned —
        it calls the blocker.
        """
        # Don't check already banned IPs
        if self.blocker.is_banned(ip):
            return

        # Get current rate for this IP
        ip_rate = self.detector.get_ip_rate(ip)

        # Get baseline mean and stddev
        mean, stddev = self.baseline.get_baseline()

        # Only check if we have a meaningful baseline
        # If mean is 0 we don't have enough data yet
        if mean == 0:
            return

        # Check if this IP has an error surge
        # An error surge means their 4xx/5xx rate is
        # 3x higher than the baseline error rate
        error_rate = self.detector.get_ip_error_rate(ip)
        baseline_error_rate = mean * 0.1
        is_error_surge = error_rate > (
            baseline_error_rate * 3
        )

        # Ask the detector if this is an anomaly
        anomalous, z_score = self.detector.is_anomaly(
            ip_rate, mean, stddev, is_error_surge
        )

        if anomalous:
            logger.warning(
                f"Anomaly detected for IP {ip} | "
                f"rate={ip_rate:.2f} mean={mean:.2f} "
                f"z={z_score:.2f}"
            )
            self.blocker.ban(
                ip,
                notifier=self.notifier,
                rate=ip_rate,
                mean=mean,
                stddev=stddev,
                z_score=z_score
            )

    def _check_global(self):
        """
        _check_global is a function that checks whether
        the total traffic from ALL IPs combined is anomalous.

        If global traffic is anomalous we send a Slack alert
        but we do NOT block anyone — we can't block
        everyone on the internet.
        """
        global_rate = self.detector.get_global_rate()
        mean, stddev = self.baseline.get_baseline()

        if mean == 0:
            return

        anomalous, z_score = self.detector.is_anomaly(
            global_rate, mean, stddev
        )

        if anomalous:
            logger.warning(
                f"Global anomaly detected | "
                f"rate={global_rate:.2f} mean={mean:.2f} "
                f"z={z_score:.2f}"
            )
            self.notifier.alert_global(
                global_rate, mean, stddev, z_score
            )

    def stop(self):
        """
        stop is a function that sets running to False
        which causes the while loop in start() to exit.
        """
        self.running = False
