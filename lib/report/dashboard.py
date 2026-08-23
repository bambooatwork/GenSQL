#!/usr/bin/env python
"""
GenSQL Report: Real-Time Web Dashboard
Author: Jeevraj
Pure Python stdlib HTTP server — no Flask/Django required.
Provides live scan progress, vulnerability count, and recent findings.
"""
import json
import threading
import time
import html
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import deque


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GenSQL Live Dashboard</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; }
.header { background: linear-gradient(135deg, #161b22, #1f2937); padding: 20px 30px;
          border-bottom: 2px solid #30363d; display: flex; justify-content: space-between; align-items: center; }
.header h1 { color: #58a6ff; font-size: 1.4em; }
.live { width: 10px; height: 10px; background: #3fb950; border-radius: 50%;
        display: inline-block; margin-right: 8px; animation: pulse 1.5s infinite; }
@keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:.3; } }
.container { padding: 24px; max-width: 1200px; margin: 0 auto; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px,1fr)); gap: 16px; margin-bottom: 24px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }
.card .num { font-size: 2.2em; font-weight: 700; color: #58a6ff; }
.card.red .num { color: #ff7b72; }
.card.orange .num { color: #ffa657; }
.card.yellow .num { color: #ffd700; }
.card.green .num { color: #3fb950; }
.card .label { color: #8b949e; font-size: .85em; margin-top: 4px; }
.events { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
.events h2 { color: #8b949e; font-size: .95em; text-transform: uppercase; margin-bottom: 16px; }
.event-row { display: flex; align-items: center; padding: 10px 0; border-bottom: 1px solid #21262d; }
.event-row:last-child { border: none; }
.event-time { color: #8b949e; font-size: .8em; width: 80px; flex-shrink: 0; font-family: monospace; }
.event-type { padding: 2px 10px; border-radius: 12px; font-size: .75em; font-weight: 700;
              text-transform: uppercase; margin-right: 12px; flex-shrink: 0; }
.et-sqli { background: #ff7b7220; color: #ff7b72; border: 1px solid #ff7b72; }
.et-info { background: #58a6ff20; color: #58a6ff; border: 1px solid #58a6ff; }
.et-waf  { background: #ffd70020; color: #ffd700; border: 1px solid #ffd700; }
.et-recon{ background: #3fb95020; color: #3fb950; border: 1px solid #3fb950; }
.et-error{ background: #f8514920; color: #f85149; border: 1px solid #f85149; }
.event-msg { font-size: .9em; word-break: break-all; }
.footer { text-align: center; padding: 20px; color: #8b949e; font-size: .8em; }
</style>
<script>
var lastCount = 0;
function update() {
  fetch('/api/status').then(r => r.json()).then(data => {
    document.getElementById('req-count').textContent  = data.requests_sent;
    document.getElementById('vuln-count').textContent = data.vulnerabilities;
    document.getElementById('crit-count').textContent = data.critical;
    document.getElementById('high-count').textContent = data.high;
    document.getElementById('payload-count').textContent = data.payloads_tried;
    document.getElementById('scan-status').textContent  = data.status;
    document.getElementById('elapsed').textContent = data.elapsed + 's';
    if (data.event_count !== lastCount) {
      lastCount = data.event_count;
      fetchEvents();
    }
  }).catch(()=>{});
}
function fetchEvents() {
  fetch('/api/events').then(r => r.json()).then(events => {
    var html = '';
    events.slice(-50).reverse().forEach(function(e) {
      var cls = 'et-' + (e.type||'info').toLowerCase().replace(/[^a-z]/g,'');
      if (['sqli','vuln','injection'].some(k=>e.type.toLowerCase().includes(k))) cls='et-sqli';
      else if (e.type.toLowerCase().includes('waf')) cls='et-waf';
      else if (e.type.toLowerCase().includes('recon')) cls='et-recon';
      else if (e.type.toLowerCase().includes('error')) cls='et-error';
      else cls='et-info';
      html += '<div class="event-row"><span class="event-time">' + e.time.split(' ')[1] + '</span>' +
              '<span class="event-type ' + cls + '">' + e.type + '</span>' +
              '<span class="event-msg">' + e.message + '</span></div>';
    });
    document.getElementById('events-list').innerHTML = html || '<div style="color:#8b949e">No events yet...</div>';
  }).catch(()=>{});
}
setInterval(update, 2000);
update(); fetchEvents();
</script>
</head>
<body>
<div class="header">
  <h1><span class="live"></span>GenSQL Live Dashboard</h1>
  <div style="color:#8b949e;font-size:.9em">by Jeevraj &nbsp;|&nbsp; Status: <span id="scan-status">Initializing</span></div>
</div>
<div class="container">
  <div class="grid">
    <div class="card red">  <div class="num" id="crit-count">0</div><div class="label">Critical</div></div>
    <div class="card orange"><div class="num" id="high-count">0</div><div class="label">High</div></div>
    <div class="card">       <div class="num" id="vuln-count">0</div><div class="label">Total Vulns</div></div>
    <div class="card">       <div class="num" id="req-count">0</div><div class="label">Requests</div></div>
    <div class="card">       <div class="num" id="payload-count">0</div><div class="label">Payloads</div></div>
    <div class="card green"> <div class="num" id="elapsed">0s</div><div class="label">Elapsed</div></div>
  </div>
  <div class="events">
    <h2>&#128248; Live Event Feed</h2>
    <div id="events-list"><div style="color:#8b949e">Waiting for events...</div></div>
  </div>
</div>
<div class="footer">GenSQL v2.0.0 &mdash; Real-Time Security Dashboard &mdash; by Jeevraj</div>
</body>
</html>"""


class Dashboard:
    """
    GenSQL Real-Time Web Dashboard — pure Python stdlib, no Flask required.
    Author: Jeevraj
    """

    def __init__(self, port=7474):
        self.port      = port
        self._server   = None
        self._thread   = None
        self._running  = False
        self._start_ts = time.time()
        self._events   = deque(maxlen=500)
        self._stats    = {
            "requests_sent":  0,
            "payloads_tried": 0,
            "vulnerabilities": 0,
            "critical":       0,
            "high":           0,
            "status":         "Scanning",
        }

    def start(self):
        """Start the dashboard HTTP server in a background daemon thread."""
        dashboard = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/" or self.path == "/index.html":
                    body = DASHBOARD_HTML.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                elif self.path == "/api/status":
                    data = dict(dashboard._stats)
                    data["elapsed"]     = "%.0f" % (time.time() - dashboard._start_ts)
                    data["event_count"] = len(dashboard._events)
                    body = json.dumps(data).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                elif self.path == "/api/events":
                    body = json.dumps(list(dashboard._events)).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, fmt, *args):
                pass  # suppress default logging

        try:
            self._server  = HTTPServer(("127.0.0.1", self.port), Handler)
            self._running = True
            self._thread  = threading.Thread(target=self._serve, daemon=True,
                                              name="GenSQL-Dashboard")
            self._thread.start()
            return True
        except OSError as ex:
            return False

    def _serve(self):
        while self._running:
            try:
                self._server.handle_request()
            except Exception:
                break

    def stop(self):
        """Shut down the dashboard server."""
        self._running = False
        if self._server:
            try:
                self._server.server_close()
            except Exception:
                pass
        self._stats["status"] = "Completed"

    # ── Public API ────────────────────────────────────────────────────────
    def add_event(self, event_type, message):
        """Add a real-time event to the dashboard feed."""
        self._events.append({
            "time":    time.strftime("%Y-%m-%d %H:%M:%S"),
            "type":    event_type,
            "message": str(message)[:200],
        })

    def update_stat(self, key, value):
        """Update a dashboard statistic."""
        if key in self._stats:
            self._stats[key] = value

    def increment(self, key, by=1):
        """Increment a numeric statistic."""
        if key in self._stats:
            self._stats[key] = self._stats.get(key, 0) + by

    def set_status(self, status):
        """Update the scan status string."""
        self._stats["status"] = status

    def record_vulnerability(self, severity, vuln_type, url, parameter):
        """Record a found vulnerability and update counters."""
        self._stats["vulnerabilities"] += 1
        if severity.upper() == "CRITICAL":
            self._stats["critical"] += 1
        elif severity.upper() == "HIGH":
            self._stats["high"] += 1
        self.add_event("SQLI", "[%s] %s in '%s' @ %s" % (severity, vuln_type, parameter, url))

    def get_url(self):
        """Return the dashboard URL."""
        return "http://127.0.0.1:%d" % self.port
