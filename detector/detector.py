import time
import logging
import yaml
from collections import deque
from threading import Lock

# Load config
with open("/app/config.yaml", "r") as f:
    config = yaml.safe_load(f)

WINDOW_SECONDS = config["detection"]["window_seconds"]
Z_THRESHOLD = config["detection"]["z_score_threshold"]
MULTIPLIER = config["detection"]["multiplier_threshold"]
STDDEV_FLOOR = config["detection"]["stddev_floor"]
ERROR_MULTIPLIER = config["detection"]["error_rate_multiplier"]

logger = logging.getLogger(__name__)


class Detector:
    """
    Detector watches per-IP and global request rates.
    It uses a sliding window deque per IP to count
    requests in the last 60 seconds.
    """

    def __init__(self):
        # ip_windows is a dictionary where each key is an IP
        # address and each value is a deque of timestamps
        # Example: {"1.2.3.4": deque([1714000001, 1714000002])}
        self.ip_windows = {}

        # ip_errors tracks error (4xx/5xx) timestamps per IP
        self.ip_errors = {}

        # global_window tracks ALL requests from ALL IPs
        self.global_window = deque()

        self.lock = Lock()

    def record(self, ip: str, status: int):
        """
        record is a function that adds a new request
        to both the per-IP window and the global window.
        It also tracks if the request was an error.

        Think of it like a bouncer at a door counting
        how many times each person has walked in
        during the last 60 seconds.
        """
        now = time.time()

        with self.lock:
            # --- Per-IP window ---
            if ip not in self.ip_windows:
                # First time we've seen this IP
                # Create a new deque for it
                self.ip_windows[ip] = deque()
                self.ip_errors[ip] = deque()

            # Add this request's timestamp to the IP's window
            self.ip_windows[ip].append(now)

            # If it's an error status, track that too
            if status >= 400:
                self.ip_errors[ip].append(now)

            # Add to global window
            self.global_window.append(now)

            # Evict old entries for this IP
            self._evict_ip(ip, now)

            # Evict old entries from global window
            self._evict_global(now)

    def _evict_ip(self, ip: str, now: float):
        """
        _evict_ip is a function that removes timestamps
        older than 60 seconds from an IP's deque.

        Example: if now is 9:01:00, anything before
        9:00:00 gets removed from the left.
        """
        cutoff = now - WINDOW_SECONDS

        while self.ip_windows[ip] and \
                self.ip_windows[ip][0] < cutoff:
            self.ip_windows[ip].popleft()

        while self.ip_errors[ip] and \
                self.ip_errors[ip][0] < cutoff:
            self.ip_errors[ip].popleft()

    def _evict_global(self, now: float):
        """
        _evict_global is a function that removes timestamps
        older than 60 seconds from the global window.
        Same idea as _evict_ip but for all traffic combined.
        """
        cutoff = now - WINDOW_SECONDS
        while self.global_window and \
                self.global_window[0] < cutoff:
            self.global_window.popleft()

    def get_ip_rate(self, ip: str) -> float:
        """
        get_ip_rate is a function that returns how many
        requests per second an IP is making right now.

        Example: if the deque has 120 timestamps in it
        and the window is 60 seconds, the rate is 2 req/s.
        """
        with self.lock:
            if ip not in self.ip_windows:
                return 0.0
            return len(self.ip_windows[ip]) / WINDOW_SECONDS

    def get_global_rate(self) -> float:
        """
        get_global_rate is a function that returns the
        total requests per second from ALL IPs combined.
        """
        with self.lock:
            return len(self.global_window) / WINDOW_SECONDS

    def get_ip_error_rate(self, ip: str) -> float:
        """
        get_ip_error_rate is a function that returns
        how many error requests per second an IP is making.
        Errors are HTTP status codes 400 and above.
        """
        with self.lock:
            if ip not in self.ip_errors:
                return 0.0
            return len(self.ip_errors[ip]) / WINDOW_SECONDS

    def is_anomaly(self, rate: float, mean: float,
                   stddev: float, is_error_surge: bool = False) -> tuple:
        """
        is_anomaly is a function that decides if a given
        rate is anomalous compared to the baseline.

        It checks two conditions:
        1. Z-score — is the rate more than 3 standard
           deviations above the mean?
        2. Multiplier — is the rate more than 5x the mean?

        If there's an error surge, thresholds are tightened —
        we become more sensitive and flag things sooner.

        Returns a tuple: (is_anomalous, z_score)
        A tuple is just two values returned together.
        """
        if stddev < STDDEV_FLOOR:
            stddev = STDDEV_FLOOR

        # Tighten thresholds if error surge detected
        z_threshold = Z_THRESHOLD
        multiplier = MULTIPLIER
        if is_error_surge:
            z_threshold = Z_THRESHOLD * 0.7
            multiplier = MULTIPLIER * 0.7

        z_score = (rate - mean) / stddev

        # Check both conditions
        z_anomaly = z_score > z_threshold
        multiplier_anomaly = mean > 0 and rate > (multiplier * mean)

        return (z_anomaly or multiplier_anomaly), z_score

    def get_top_ips(self, n: int = 10) -> list:
        """
        get_top_ips is a function that returns the top N
        IPs by current request rate. Used by the dashboard
        to show who is making the most requests right now.
        """
        with self.lock:
            rates = {
                ip: len(window) / WINDOW_SECONDS
                for ip, window in self.ip_windows.items()
            }
            # sorted() is a function that sorts a list
            # reverse=True means highest first
            sorted_ips = sorted(
                rates.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_ips[:n]
