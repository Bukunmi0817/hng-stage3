import time
import logging
import threading

logger = logging.getLogger(__name__)


class Unbanner:
    """
    Unbanner runs as a background thread that continuously
    checks if any banned IPs should be released based on
    their ban duration and how long they have been banned.

    Think of it like a prison warden who walks down the
    corridor every 30 seconds checking if anyone's
    sentence has expired.
    """

    def __init__(self, blocker, notifier):
        # blocker is the Blocker object we wrote earlier
        # We need it to check banned IPs and call unban()
        self.blocker = blocker

        # notifier is the Notifier object
        # We pass it to unban() so it can send Slack alerts
        self.notifier = notifier

        # running controls the infinite loop
        # When we want to stop the unbanner we set this to False
        self.running = True

    def start(self):
        """
        start is a function that creates a background thread
        and starts the unbanner loop inside it.

        A thread is like hiring a second worker to do a job
        at the same time as your main worker.
        The main program keeps running while this thread
        quietly checks bans in the background.
        """
        thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="unbanner"
        )
        thread.start()
        logger.info("Unbanner thread started")

    def _run(self):
        """
        _run is the main loop of the unbanner.
        It runs forever, checking every 30 seconds
        if any bans have expired.

        Why 30 seconds? Because our shortest ban is
        600 seconds (10 minutes). Checking every 30
        seconds means we'll never be more than 30
        seconds late releasing someone.
        """
        while self.running:
            self._check_bans()
            time.sleep(30)

    def _check_bans(self):
        """
        _check_bans is a function that looks at every
        currently banned IP and checks if their ban
        duration has expired.

        It gets a snapshot of banned IPs, loops through
        them, and calls unban() on anyone whose time is up.
        """
        # get_banned_ips() returns a copy of the dictionary
        # We use a copy so we can safely loop through it
        # while the blocker might be modifying the original
        banned = self.blocker.get_banned_ips()
        now = time.time()

        for ip, info in banned.items():
            duration = info["duration"]

            # duration of -1 means permanent ban
            # Skip these — they never get released
            if duration == -1:
                continue

            banned_at = info["banned_at"]
            time_banned = now - banned_at

            # Has the ban duration expired?
            if time_banned >= duration:
                logger.info(
                    f"Ban expired for {ip} after "
                    f"{time_banned:.0f}s "
                    f"(duration was {duration}s)"
                )
                self.blocker.unban(
                    ip,
                    notifier=self.notifier,
                    reason=f"Ban expired after {duration}s"
                )

    def stop(self):
        """
        stop is a function that sets running to False
        which causes the while loop in _run to exit
        on its next iteration.
        """
        self.running = False
