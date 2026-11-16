"""A scan job: runs the collectors in order and keeps module status, progress and results."""
import datetime as dt
import threading
import time
import traceback

from . import collectors, net, report

PASSIVE_MODULES = ["whois", "dns", "subdomains", "ssl", "hosts", "threat"]
LIVE_MODULES = ["headers"]
ORDER = ["whois", "dns", "subdomains", "ssl", "hosts", "threat", "headers"]
ALLOWED_MODULES = set(ORDER)
MAX_HOST_CHECKS = 100  # names checked in DNS per scan
MAX_LIVE_PROBES = 25  # names contacted over HTTPS per authorized scan


class SkipModule(Exception):
    """A module that cannot run in this setup, such as a missing API key. Shown as skipped, not failed."""


def _utc_iso(timestamp):
    return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat()


def _days_left(iso_text):
    if not iso_text:
        return None
    try:
        expires = dt.datetime.fromisoformat(iso_text)
    except ValueError:
        return None
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=dt.timezone.utc)
    return (expires - dt.datetime.now(dt.timezone.utc)).days


class ScanJob:
    def __init__(self, scan_id, domain, modules, live=False):
        self.id = scan_id
        self.domain = domain
        self.live = bool(live)
        chosen = set(modules)
        if "hosts" in chosen:
            chosen.add("subdomains")  # name checks need the names that certificate logs provide
        self.requested = [m for m in ORDER if m in chosen and (self.live or m not in LIVE_MODULES)]
        self.status = "running"
        self.progress = 0
        self.modules = {name: {"status": "queued"} for name in self.requested}
        self.results = {"domain": domain, "live": {} if self.live else None, "warnings": []}
        self.error = None
        self.started = time.time()
        self.finished = None
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._ct = None  # certificate-log entries, fetched once and shared by two modules

    # ---- public API used by the server ----

    def cancel(self):
        self._cancel.set()

    def is_active(self):
        with self._lock:
            return self.status == "running"

    def view(self):
        with self._lock:
            data = {
                "scan_id": self.id,
                "domain": self.domain,
                "status": self.status,
                "progress": self.progress,
                "modules": {name: dict(info) for name, info in self.modules.items()},
                "live": self.live,
                "error": self.error,
            }
            if self.status == "completed":
                data["results"] = self.results
                data["finished_at"] = _utc_iso(self.finished)
                data["duration_seconds"] = round(self.finished - self.started, 1)
            return data

    # ---- run in a background thread ----

    def run(self):
        done = 0
        for name in self.requested:
            if self._cancel.is_set():
                break
            self._set_module(name, status="running")
            try:
                count = getattr(self, "_collect_" + name)()
                self._set_module(name, status="done", count=count)
            except SkipModule as note:
                self._set_module(name, status="skipped", message=str(note))
            except net.NetError as err:
                self._set_module(name, status="failed", message=str(err))
            except Exception:  # keep the engine alive; the console shows the detail
                traceback.print_exc()
                self._set_module(name, status="failed", message="Unexpected engine error. See the engine window.")
            done += 1
            with self._lock:
                self.progress = round(100 * done / max(1, len(self.requested)))
        self._finish()

    def _set_module(self, name, status, count=None, message=None):
        with self._lock:
            info = {"status": status}
            if count is not None:
                info["count"] = count
            if message:
                info["message"] = message
                if status == "failed":
                    self.results["warnings"].append(f"{name}: {message}")
            self.modules[name] = info

    def _finish(self):
        with self._lock:
            self.finished = time.time()
            statuses = [info["status"] for info in self.modules.values()]
            if self._cancel.is_set():
                self.status = "cancelled"
            elif "done" in statuses:
                self.status = "completed"
                self.progress = 100
                self.results["observations"] = report.observations(self.results, self.modules)
            else:
                self.status = "failed"
                messages = [info.get("message") for info in self.modules.values() if info.get("message")]
                self.error = {
                    "code": "ALL_SOURCES_FAILED",
                    "message": messages[0] if messages else "No source returned data for this domain.",
                }

    # ---- collectors: each returns the count shown next to its module ----

    def _collect_whois(self):
        details = collectors.rdap(self.domain)
        self.results["domain_details"] = details
        return 1 if details.get("found") else 0

    def _collect_dns(self):
        records = collectors.dns_records(self.domain)
        self.results["dns"] = records
        self.results["dns_notes"] = collectors.dns_notes(records)
        self.results["email_security"] = collectors.email_security(self.domain, records)
        return len(records)

    def _collect_subdomains(self):
        entries = self._certificate_log()
        details, wildcard_seen = collectors.subdomains_from_ct(entries, self.domain)
        self.results["subdomains"] = [item["name"] for item in details]
        self.results["subdomain_details"] = details
        self.results["wildcard_certificates_seen"] = wildcard_seen
        return len(details)

    def _collect_ssl(self):
        entries = self._certificate_log()
        certs = collectors.certificates_from_ct(entries, self.domain)
        self.results["certificates"] = certs
        latest = certs[0] if certs else None
        ssl_summary = {
            "issuer": latest["issuer"] if latest else None,
            "valid_until": latest["not_after"] if latest else None,
            "days_left": _days_left(latest["not_after"]) if latest else None,
            "protocol": None,
            "grade": None,
            "source": collectors.CT_SOURCE,
        }
        self.results["ssl"] = ssl_summary
        if self.live:
            try:
                tls = net.tls_certificate(self.domain)
                self.results["live"]["tls"] = tls
                ssl_summary.update(
                    issuer=tls["issuer"],
                    valid_until=tls["not_after"],
                    days_left=_days_left(tls["not_after"]),
                    protocol=tls["protocol"],
                )
            except net.NetError as err:
                self.results["live"]["tls_error"] = str(err)
        return len(certs)

    def _collect_hosts(self):
        details = self.results.get("subdomain_details") or []
        if not details:
            raise SkipModule("No names were found in certificate logs, so there is nothing to check.")
        checked = details[:MAX_HOST_CHECKS]
        resolved = collectors.resolve_names([item["name"] for item in checked])
        unknown = 0
        for item in checked:
            info = resolved[item["name"]]
            item["resolves"] = info["resolves"]
            item["addresses"] = info["addresses"]
            if info["resolves"] is None:
                unknown += 1
        if unknown == len(checked):
            raise net.NetError("No DNS resolver answered, so the names could not be checked.")
        resolving = sum(1 for item in checked if item["resolves"])
        self.results["hosts"] = {
            "checked": len(checked),
            "truncated": len(details) > MAX_HOST_CHECKS,
            "resolving": resolving,
            "unknown": unknown,
            "source": collectors.DNS_SOURCE,
        }
        if self.live:
            self._probe_live_hosts(checked)
        return resolving

    def _probe_live_hosts(self, checked):
        """Authorized scans only: one HTTPS request to each resolving name, up to the probe limit."""
        candidates = [item for item in checked if item.get("resolves")][:MAX_LIVE_PROBES]
        responding = 0
        for item in candidates:
            if self._cancel.is_set():
                break
            try:
                probe = net.http_probe(item["name"])
                item.update(verified_live=True, http_status=probe["status"], server=probe["server"])
                responding += 1
            except net.NetError as err:
                item.update(verified_live=False, probe_error=str(err))
        self.results["live"]["hosts"] = {
            "probed": len(candidates),
            "responding": responding,
            "limit": MAX_LIVE_PROBES,
            "source": net.PROBE_SOURCE,
        }

    def _collect_threat(self):
        result = collectors.threat_intel(self.domain)
        if result["verdict"] == "not_configured":
            raise SkipModule("No threat intelligence key is set on the engine (CYBROT_VT_API_KEY or CYBROT_OTX_API_KEY).")
        self.results["threat_intel"] = result
        return len(result["providers"])

    def _collect_headers(self):
        try:
            self.results["live"]["headers"] = net.http_headers(self.domain)
        except net.NetError as err:
            self.results["live"]["headers_error"] = str(err)
            raise
        return sum(1 for value in self.results["live"]["headers"]["headers"].values() if value)

    def _certificate_log(self):
        if self._ct is None:
            self._ct = collectors.ct_entries(self.domain)
        return self._ct
