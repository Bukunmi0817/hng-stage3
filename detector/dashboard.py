import time
import threading
import logging
import psutil
import yaml
from http.server import HTTPServer, BaseHTTPRequestHandler

with open("/app/config.yaml", "r") as f:
    config = yaml.safe_load(f)

PORT = config["server"]["port"]
HOST = config["server"]["host"]

logger = logging.getLogger(__name__)

START_TIME = time.time()


class DashboardHandler(BaseHTTPRequestHandler):
    blocker = None
    detector = None
    baseline = None

    def do_GET(self):
        if self.path == "/health":
            self._send_response(200, "OK")
            return
        html = self._build_page()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def _send_response(self, code: int, body: str):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def _build_page(self) -> str:
        banned = DashboardHandler.blocker.get_banned_ips()
        global_rate = DashboardHandler.detector.get_global_rate()
        top_ips = DashboardHandler.detector.get_top_ips(10)
        mean, stddev = DashboardHandler.baseline.get_baseline()

        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent

        uptime_seconds = int(time.time() - START_TIME)
        uptime_str = _format_uptime(uptime_seconds)

        banned_rows = ""
        for ip, info in banned.items():
            duration = info["duration"]
            duration_str = "PERMANENT" if duration == -1 \
                else f"{duration}s"
            banned_at = time.strftime(
                "%H:%M:%S",
                time.gmtime(info["banned_at"])
            )
            offense = info["offense_count"]
            banned_rows += (
                f"<tr>"
                f"<td>{ip}</td>"
                f"<td>{banned_at}</td>"
                f"<td>{duration_str}</td>"
                f"<td>{offense}</td>"
                f"</tr>"
            )

        if not banned_rows:
            banned_rows = (
                "<tr><td colspan='4' "
                "style='text-align:center;color:#888'>"
                "No banned IPs</td></tr>"
            )

        ip_rows = ""
        for ip, rate in top_ips:
            ip_rows += (
                f"<tr>"
                f"<td>{ip}</td>"
                f"<td>{rate:.2f}</td>"
                f"</tr>"
            )

        if not ip_rows:
            ip_rows = (
                "<tr><td colspan='2' "
                "style='text-align:center;color:#888'>"
                "No traffic yet</td></tr>"
            )

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>HNG Anomaly Detection Engine</title>
    <meta http-equiv="refresh" content="3">
    <meta charset="UTF-8">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: Arial, sans-serif;
            background: #ffffff;
            color: #111111;
            padding: 30px;
        }}
        .header {{
            border-bottom: 3px solid #111;
            padding-bottom: 15px;
            margin-bottom: 25px;
        }}
        .header h1 {{
            font-size: 28px;
            font-weight: bold;
            color: #111111;
        }}
        .status {{
            display: inline-block;
            margin-top: 8px;
            background: #111111;
            color: #ffffff;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 13px;
            font-weight: bold;
            letter-spacing: 1px;
        }}
        h2 {{
            font-size: 13px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: #555555;
            margin: 30px 0 12px 0;
            border-bottom: 1px solid #dddddd;
            padding-bottom: 6px;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
        }}
        .metric {{
            background: #f5f5f5;
            border: 1px solid #dddddd;
            border-radius: 6px;
            padding: 18px;
        }}
        .metric-label {{
            color: #777777;
            font-size: 12px;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .metric-value {{
            color: #111111;
            font-size: 26px;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            border: 1px solid #dddddd;
            border-radius: 6px;
            overflow: hidden;
        }}
        th {{
            background: #111111;
            color: #ffffff;
            padding: 10px 14px;
            text-align: left;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        td {{
            padding: 10px 14px;
            border-top: 1px solid #eeeeee;
            font-size: 13px;
            color: #111111;
        }}
        tr:hover td {{
            background: #f9f9f9;
        }}
        .timestamp {{
            color: #999999;
            font-size: 12px;
            margin-top: 30px;
            border-top: 1px solid #eeeeee;
            padding-top: 15px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>HNG Anomaly Detection Engine</h1>
        <span class="status">ACTIVE</span>
    </div>

    <h2>System Metrics</h2>
    <div class="metrics">
        <div class="metric">
            <div class="metric-label">Global Req/s</div>
            <div class="metric-value">{global_rate:.2f}</div>
        </div>
        <div class="metric">
            <div class="metric-label">CPU Usage</div>
            <div class="metric-value">{cpu:.1f}%</div>
        </div>
        <div class="metric">
            <div class="metric-label">Memory Usage</div>
            <div class="metric-value">{mem:.1f}%</div>
        </div>
        <div class="metric">
            <div class="metric-label">Baseline Mean</div>
            <div class="metric-value">{mean:.2f}</div>
        </div>
        <div class="metric">
            <div class="metric-label">Baseline Stddev</div>
            <div class="metric-value">{stddev:.2f}</div>
        </div>
        <div class="metric">
            <div class="metric-label">Uptime</div>
            <div class="metric-value">{uptime_str}</div>
        </div>
    </div>

    <h2>Banned IPs ({len(banned)})</h2>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Banned At</th>
            <th>Duration</th>
            <th>Offense #</th>
        </tr>
        {banned_rows}
    </table>

    <h2>Top 10 Source IPs</h2>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Req/s</th>
        </tr>
        {ip_rows}
    </table>

    <p class="timestamp">
        Last updated: {time.strftime("%Y-%m-%d %H:%M:%S UTC",
        time.gmtime())}
        &nbsp;|&nbsp; Auto-refreshes every 3 seconds
    </p>
</body>
</html>"""
        return html

    def log_message(self, format, *args):
        pass


def _format_uptime(seconds: int) -> str:
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours}h {minutes}m {secs}s"


class Dashboard:
    def __init__(self, blocker, detector, baseline):
        DashboardHandler.blocker = blocker
        DashboardHandler.detector = detector
        DashboardHandler.baseline = baseline

    def start(self):
        server = HTTPServer((HOST, PORT), DashboardHandler)
        thread = threading.Thread(
            target=server.serve_forever,
            daemon=True,
            name="dashboard"
        )
        thread.start()
        logger.info(f"Dashboard running on port {PORT}")
