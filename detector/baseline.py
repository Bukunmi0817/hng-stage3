import time
import math
import logging
import yaml
from collections import deque
from threading import Lock

# Load config
with open("/app/config.yaml", "r") as f:
    config = yaml.safe_load(f)

BASELINE_WINDOW = config["detection"]["baseline_window_minutes"] * 60
RECALC_INTERVAL = config["detection"]["baseline_recalc_interval"]
MIN_REQUESTS = config["detection"]["min_requests_for_baseline"]
STDDEV_FLOOR = config["detection"]["stddev_floor"]

logger = logging.getLogger(__name__)


class Baseline:
    """
    Baseline is a class that tracks traffic over time and
    computes mean and standard deviation of request rates.
    It maintains a 30-minute rolling window of per-second counts.
    """

    def __init__(self):
        # per_second_counts is a deque that stores
        # (timestamp, count) tuples for each second
        self.per_second_counts = deque()

        # current_second tracks which second we are in
        self.current_second = int(time.time())
        self.current_count = 0

        # effective_mean and effective_stddev are the
        # computed baseline values used for detection
        self.effective_mean = 0.0
        self.effective_stddev = STDDEV_FLOOR

        # last_recalc tracks when we last recomputed
        self.last_recalc = time.time()

        # lock prevents two threads from updating
        # the baseline at the same time
        self.lock = Lock()

    def record_request(self):
        """
        record_request is a function that increments
        the counter for the current second every time
        a new HTTP request arrives.
        """
        with self.lock:
            now = int(time.time())
            if now != self.current_second:
                # We moved to a new second
                # Save the previous second's count
                self.per_second_counts.append(
                    (self.current_second, self.current_count)
                )
                self.current_second = now
                self.current_count = 1
                # Evict old entries outside the 30-minute window
                self._evict_old()
            else:
                self.current_count += 1

            # Recalculate baseline every 60 seconds
            if time.time() - self.last_recalc >= RECALC_INTERVAL:
                self._recalculate()

    def _evict_old(self):
        """
        _evict_old is a function that removes entries
        from the left of the deque that are older than
        the 30-minute baseline window.
        This is what makes it a SLIDING window —
        old data falls off the left as new data
        comes in on the right.
        """
        cutoff = time.time() - BASELINE_WINDOW
        while self.per_second_counts and \
                self.per_second_counts[0][0] < cutoff:
            self.per_second_counts.popleft()

    def _recalculate(self):
        """
        _recalculate is a function that computes the mean
        and standard deviation from all the per-second
        counts currently in the deque.
        It only runs if we have enough data points.
        """
        counts = [c for _, c in self.per_second_counts]

        if len(counts) < MIN_REQUESTS:
            logger.info("Not enough data for baseline yet")
            self.last_recalc = time.time()
            return

        # mean is the average — sum divided by count
        mean = sum(counts) / len(counts)

        # variance is the average of squared differences from mean
        variance = sum((c - mean) ** 2 for c in counts) / len(counts)

        # stddev is the square root of variance
        stddev = math.sqrt(variance)

        # Apply floor to prevent division by zero in detector
        if stddev < STDDEV_FLOOR:
            stddev = STDDEV_FLOOR

        self.effective_mean = mean
        self.effective_stddev = stddev
        self.last_recalc = time.time()

        logger.info(
            f"[BASELINE RECALC] mean={mean:.2f} "
            f"stddev={stddev:.2f} "
            f"samples={len(counts)}"
        )

    def get_baseline(self):
        """
        get_baseline is a function that returns the current
        mean and stddev values for use by the detector.
        """
        with self.lock:
            return self.effective_mean, self.effective_stddev
