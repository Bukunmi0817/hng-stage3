# HNG Stage 3 — Anomaly Detection Engine

A real-time HTTP traffic anomaly detection and DDoS mitigation daemon built
alongside a Nextcloud deployment. Monitors nginx access logs, learns normal
traffic patterns, and automatically blocks suspicious IPs using iptables.

## Live URLs

- **Server IP:** 63.32.56.42
- **Nextcloud:** http://63.32.56.42 (IP access only)
- **Metrics Dashboard:** http://stage3.duckdns.org:9000

## Language Choice

Built in Python because it is fast to write, easy to audit, has threading
and json built into the standard library, and psutil makes system metrics
trivial to collect.

## How the Sliding Window Works

Each IP gets its own deque of request timestamps. Every time a request arrives,
the current timestamp is appended to the right. Any timestamps older than 60
seconds are removed from the left. The current rate = length of deque / 60.

This is a true sliding window with no per-minute resets. It always reflects
exactly the last 60 seconds of traffic.

## How the Baseline Works

Every second the per-second request count is recorded in a 30-minute rolling
deque. Every 60 seconds, mean and standard deviation are recalculated from all
counts. A stddev floor of 1.0 prevents division by zero. The baseline only
activates after enough data points are collected.

## How Detection Makes a Decision

Two conditions are checked. Either one firing triggers a block:

1. Z-Score above 3.0
   z = (current_rate - mean) / stddev
   If z > 3.0 the rate is more than 3 standard deviations above normal.

2. 5x Multiplier
   If current_rate > 5 * mean, flag as anomalous regardless of z-score.

If an IP has an error surge (4xx/5xx rate 3x above baseline), thresholds
are tightened automatically.

## How iptables Blocks an IP

When an anomaly is detected the blocker runs:
    iptables -I INPUT -s 1.2.3.4 -j DROP

This inserts a DROP rule at the top of the INPUT chain. Packets from the
banned IP are silently discarded at the kernel level before nginx sees them.

Ban schedule (exponential backoff):
- First offense: 10 minutes (600s)
- Second offense: 30 minutes (1800s)
- Third offense: 2 hours (7200s)
- Fourth and beyond: Permanent

## Setup Instructions (Fresh VPS)

Prerequisites: Ubuntu 22.04+, 2 vCPU, 2GB RAM, ports 80 and 9000 open.

1. Install Docker:
   curl -fsSL https://get.docker.com | sudo sh
   sudo usermod -aG docker $USER && newgrp docker

2. Clone the repository:
   git clone https://github.com/Bukunmi0817/hng-stage3.git
   cd hng-stage3

3. Add your Slack webhook to detector/config.yaml

4. Add your IPs to the whitelist in detector/config.yaml

5. Start the stack:
   docker compose up -d --build

6. View dashboard at http://YOUR_SERVER_IP:9000

## Repository Structure

    detector/
      main.py        - Entry point, starts all components
      monitor.py     - Tails nginx log, parses JSON lines
      baseline.py    - Rolling 30-minute traffic baseline
      detector.py    - Sliding window and anomaly detection
      blocker.py     - iptables ban/unban and audit log
      unbanner.py    - Background thread, releases expired bans
      notifier.py    - Slack webhook alerts
      dashboard.py   - Live metrics web server on port 9000
      config.yaml    - All thresholds and settings
      Dockerfile     - Container definition
    nginx/
      nginx.conf     - Reverse proxy and JSON access logging
    docker-compose.yml
    README.md

## GitHub Repository

https://github.com/Bukunmi0817/hng-stage3

## Blog Post

https://medium.com/@adeshipob/how-to-build-a-anomaly-detection-engine-ddos-detection-tool-b6184f4fc447
