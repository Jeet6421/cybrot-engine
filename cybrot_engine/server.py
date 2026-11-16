"""Local HTTP API used by the browser extension. Listens on 127.0.0.1 only."""
import argparse
import json
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import VERSION, collectors, net, report, scanner

HOST = "127.0.0.1"
MAX_ACTIVE_SCANS = 2
MAX_BODY_BYTES = 4096
SCAN_PATH = re.compile(r"^/api/scans/([0-9a-f]{16})(/cancel|/report\.(html|csv|json|pdf))?$")

_jobs = {}
_jobs_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = "CYBROT-engine"

    def log_message(self, format, *args):
        pass  # the console stays quiet; errors are printed where they happen

    # ---- helpers ----

    def _host_ok(self):
        port = self.server.server_port
        return self.headers.get("Host", "") in (f"{HOST}:{port}", f"localhost:{port}")

    def _send(self, code, payload=None, body=None, content_type="application/json; charset=utf-8"):
        if body is None:
            body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, error_code, message):
        self._send(code, {"error": {"code": error_code, "message": message}})

    def _job(self, scan_id):
        with _jobs_lock:
            return _jobs.get(scan_id)

    # ---- routes ----

    def do_OPTIONS(self):
        self._send(204, body=b"")

    def do_GET(self):
        if not self._host_ok():
            return self._error(400, "BAD_HOST", "Requests must use 127.0.0.1 or localhost.")
        path = urlsplit(self.path).path
        if path == "/api/health":
            return self._send(200, {"status": "ok", "engine": "cybrot", "version": VERSION, "mode": "passive-default"})
        match = SCAN_PATH.match(path)
        if not match:
            return self._error(404, "NOT_FOUND", "Unknown endpoint.")
        job = self._job(match.group(1))
        if job is None:
            return self._error(404, "NOT_FOUND", "Scan not found.")
        suffix = match.group(2)
        if suffix is None:
            return self._send(200, job.view())
        if suffix == "/cancel":
            return self._error(405, "METHOD_NOT_ALLOWED", "Use POST to cancel a scan.")
        view = job.view()
        if view["status"] != "completed":
            return self._error(409, "NOT_READY", "A report is available when the scan has completed.")
        fmt = match.group(3)
        if fmt == "html":
            return self._send(200, body=report.render_html(view).encode("utf-8"), content_type="text/html; charset=utf-8")
        if fmt == "csv":
            return self._send(200, body=report.render_csv(view).encode("utf-8"), content_type="text/csv; charset=utf-8")
        if fmt == "pdf":
            return self._send(200, body=report.render_pdf(view), content_type="application/pdf")
        return self._send(200, body=report.render_json(view).encode("utf-8"))

    def do_POST(self):
        if not self._host_ok():
            return self._error(400, "BAD_HOST", "Requests must use 127.0.0.1 or localhost.")
        path = urlsplit(self.path).path
        if path == "/api/scans":
            return self._create_scan()
        match = SCAN_PATH.match(path)
        if match and match.group(2) == "/cancel":
            job = self._job(match.group(1))
            if job is None:
                return self._error(404, "NOT_FOUND", "Scan not found.")
            job.cancel()
            return self._send(200, {"scan_id": job.id, "status": "cancelling"})
        return self._error(404, "NOT_FOUND", "Unknown endpoint.")

    def _create_scan(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._error(400, "BAD_REQUEST", "Content-Length is not a number.")
        if length > MAX_BODY_BYTES:
            return self._error(413, "TOO_LARGE", "The request is too large.")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._error(400, "BAD_JSON", "The request body is not valid JSON.")
        if not isinstance(data, dict):
            return self._error(400, "BAD_JSON", "The request body must be a JSON object.")

        try:
            domain = net.normalize_domain(data.get("domain"))
        except net.TargetError as err:
            return self._error(400, "INVALID_DOMAIN", str(err))

        if data.get("passive_only", True) is not True:
            return self._error(400, "ACTIVE_NOT_SUPPORTED", "Active checks are not available. Scans are passive-only.")
        live = data.get("live", False)
        authorized = data.get("authorized", False)
        if not isinstance(live, bool) or not isinstance(authorized, bool):
            return self._error(400, "BAD_FLAG", "'live' and 'authorized' must be true or false.")
        if live and not authorized:
            return self._error(
                400, "AUTHORIZATION_REQUIRED",
                "Live checks connect to the domain and to the names found for it (up to 25). Confirm you own them or are authorized to test them.",
            )

        requested = data.get("modules", scanner.PASSIVE_MODULES)
        if not isinstance(requested, list):
            return self._error(400, "BAD_MODULES", "'modules' must be a list.")
        modules = [m for m in requested if m in scanner.ALLOWED_MODULES]
        if not modules:
            return self._error(400, "NO_MODULES", "Choose at least one module.")

        with _jobs_lock:
            active = sum(1 for job in _jobs.values() if job.is_active())
            if active >= MAX_ACTIVE_SCANS:
                return self._error(429, "TOO_MANY_SCANS", "Wait for a running scan to finish before starting another.")
            scan_id = secrets.token_hex(8)
            job = scanner.ScanJob(scan_id, domain, modules, live=live)
            _jobs[scan_id] = job
        threading.Thread(target=job.run, name=f"scan-{scan_id}", daemon=True).start()
        return self._send(202, {"scan_id": scan_id})


def main(argv=None):
    parser = argparse.ArgumentParser(description="CYBROT OSINT local engine")
    parser.add_argument("--port", type=int, default=8000, help="port on 127.0.0.1 (default 8000)")
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer((HOST, args.port), Handler)
    print(f"CYBROT engine {VERSION} on http://{HOST}:{args.port} (passive sources; live checks need authorization)")
    providers = collectors.configured_threat_keys()
    if providers:
        names = ", ".join(collectors.THREAT_NAMES[name] for name in providers)
        print(f"Threat intelligence: {names} (keys read from environment variables; never sent to the extension)")
    else:
        print("Threat intelligence: not configured. Set CYBROT_VT_API_KEY or CYBROT_OTX_API_KEY to enable it.")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Engine stopped.")
    finally:
        server.server_close()
