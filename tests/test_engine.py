"""Engine tests. Outside sources are replaced with fixtures, so these run without internet access.

Run from the engine folder:  python3 -m unittest discover -s tests -v
"""
import json
import pathlib
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from cybrot_engine import collectors, net, report, scanner, server  # noqa: E402


class TargetTests(unittest.TestCase):
    def test_accepts_plain_and_url_forms(self):
        self.assertEqual(net.normalize_domain("Example.COM"), "example.com")
        self.assertEqual(net.normalize_domain("https://www.example.com/path?x=1"), "www.example.com")
        self.assertEqual(net.normalize_domain("example.com."), "example.com")

    def test_rejects_ips_localhost_and_junk(self):
        for bad in ["127.0.0.1", "localhost", "", "exa mple.com", "-bad.com", "example", "a" * 70 + ".com"]:
            with self.subTest(value=bad), self.assertRaises(net.TargetError):
                net.normalize_domain(bad)

    def test_refuses_loopback_address_before_any_live_request(self):
        # localhost resolves on the local machine, so this needs no internet access.
        with self.assertRaises(net.TargetError):
            net.public_address("localhost")


class CollectorTests(unittest.TestCase):
    def test_subdomains_are_deduplicated_filtered_and_dated(self):
        entries = [
            {"name_value": "www.example.com\nmail.example.com", "entry_timestamp": "2024-05-01T10:00:00"},
            {"name_value": "www.example.com", "entry_timestamp": "2023-01-01T10:00:00"},
            {"name_value": "*.example.com\napi.example.com", "entry_timestamp": "2025-02-01T10:00:00"},
            {"name_value": "otherdomain.org", "entry_timestamp": "2025-02-01T10:00:00"},
            {"name_value": "example.com", "entry_timestamp": "2025-02-01T10:00:00"},
        ]
        details, wildcard = collectors.subdomains_from_ct(entries, "example.com")
        names = [d["name"] for d in details]
        self.assertEqual(names, ["api.example.com", "mail.example.com", "www.example.com"])
        www = next(d for d in details if d["name"] == "www.example.com")
        self.assertEqual(www["first_seen"], "2023-01-01T10:00:00")
        self.assertTrue(all(d["verified_live"] is False for d in details))
        self.assertTrue(wildcard)

    def test_certificates_are_sorted_newest_expiry_first(self):
        entries = [
            {"id": 1, "name_value": "example.com", "issuer_name": "CN=A", "not_before": "2024-01-01T00:00:00",
             "not_after": "2025-01-01T00:00:00"},
            {"id": 2, "name_value": "www.example.com", "issuer_name": "CN=B", "not_before": "2025-06-01T00:00:00",
             "not_after": "2026-06-01T00:00:00"},
            {"id": 3, "name_value": "unrelated.org", "issuer_name": "CN=C", "not_before": "2025-06-01T00:00:00",
             "not_after": "2027-06-01T00:00:00"},
        ]
        certs = collectors.certificates_from_ct(entries, "example.com")
        self.assertEqual([c["crt_sh_id"] for c in certs], [2, 1])
        self.assertTrue(certs[0]["not_after"].startswith("2026-06-01T00:00:00"))

    def test_dns_parsing_strips_quotes_and_ignores_cname_chains(self):
        answers = {
            "A": {"Status": 0, "Answer": [{"type": 5, "data": "alias.example.net.", "TTL": 60},
                                          {"type": 1, "data": "192.0.2.10", "TTL": 300}]},
            "TXT": {"Status": 0, "Answer": [{"type": 16, "data": '"v=spf1 include:_spf.example.net ~all"', "TTL": 3600}]},
        }

        def fake_doh(name, rtype):
            return answers.get(rtype, {"Status": 0})

        with mock.patch("cybrot_engine.net.doh_query", side_effect=fake_doh):
            records = collectors.dns_records("example.com")
        self.assertIn({"type": "A", "value": "192.0.2.10", "ttl": 300, "source": collectors.DNS_SOURCE}, records)
        self.assertFalse(any(r["value"].startswith("alias") for r in records))
        txt = next(r for r in records if r["type"] == "TXT")
        self.assertEqual(txt["value"], "v=spf1 include:_spf.example.net ~all")

    def test_email_security_reads_spf_and_dmarc_policy(self):
        records = [{"type": "TXT", "value": "v=spf1 -all", "ttl": 1, "source": "x"}]

        def fake_doh(name, rtype):
            return {"Answer": [{"type": 16, "data": '"v=DMARC1; p=reject; rua=mailto:x@example.com"'}]}

        with mock.patch("cybrot_engine.net.doh_query", side_effect=fake_doh):
            result = collectors.email_security("example.com", records)
        self.assertEqual(result["spf"], "v=spf1 -all")
        self.assertEqual(result["dmarc_policy"], "reject")
        self.assertIn("Not checked", result["dkim"])


class ScanJobTests(unittest.TestCase):
    def _patches(self, ct_error=None):
        ct = mock.patch("cybrot_engine.collectors.ct_entries",
                        side_effect=net.NetError("crt.sh timed out.") if ct_error else None,
                        return_value=[{"id": 9, "name_value": "www.example.com", "issuer_name": "CN=Test CA",
                                       "not_before": "2025-01-01T00:00:00", "not_after": "2099-01-01T00:00:00",
                                       "entry_timestamp": "2025-01-02T00:00:00"}])
        rdap = mock.patch("cybrot_engine.collectors.rdap",
                          return_value={"found": True, "registrar": "Test Registrar", "created": "1995-01-01",
                                        "expires": "2030-01-01", "name_servers": ["ns1.example.net"],
                                        "source": collectors.RDAP_SOURCE})
        dns = mock.patch("cybrot_engine.collectors.dns_records",
                         return_value=[{"type": "A", "value": "192.0.2.10", "ttl": 300, "source": "x"}])
        email = mock.patch("cybrot_engine.collectors.email_security",
                           return_value={"spf": None, "dmarc": None, "dmarc_policy": None, "dkim": "n/a", "source": "x"})
        return ct, rdap, dns, email

    def test_passive_scan_completes_with_real_shape(self):
        ct, rdap, dns, email = self._patches()
        with ct, rdap, dns, email:
            job = scanner.ScanJob("abc", "example.com", scanner.PASSIVE_MODULES)
            job.run()
        view = job.view()
        self.assertEqual(view["status"], "completed")
        self.assertEqual(view["progress"], 100)
        self.assertEqual(view["results"]["subdomains"], ["www.example.com"])
        self.assertEqual(view["results"]["ssl"]["issuer"], "CN=Test CA")
        self.assertEqual(view["results"]["domain_details"]["registrar"], "Test Registrar")
        self.assertIsNone(view["results"]["ssl"]["protocol"])  # passive scans cannot know the TLS version
        self.assertEqual(view["modules"]["subdomains"]["count"], 1)
        self.assertIn("finished_at", view)

    def test_one_failed_source_keeps_the_rest(self):
        ct, rdap, dns, email = self._patches(ct_error=True)
        with ct, rdap, dns, email:
            job = scanner.ScanJob("def", "example.com", scanner.PASSIVE_MODULES)
            job.run()
        view = job.view()
        self.assertEqual(view["status"], "completed")
        self.assertEqual(view["modules"]["subdomains"]["status"], "failed")
        self.assertIn("crt.sh timed out", view["modules"]["subdomains"]["message"])
        self.assertEqual(view["modules"]["whois"]["status"], "done")
        self.assertTrue(any("subdomains" in w for w in view["results"]["warnings"]))

    def test_all_sources_failing_reports_failed_scan(self):
        with mock.patch("cybrot_engine.collectors.rdap", side_effect=net.NetError("RDAP down.")), \
                mock.patch("cybrot_engine.collectors.dns_records", side_effect=net.NetError("DNS down.")), \
                mock.patch("cybrot_engine.collectors.ct_entries", side_effect=net.NetError("CT down.")):
            job = scanner.ScanJob("ghi", "example.com", scanner.PASSIVE_MODULES)
            job.run()
        view = job.view()
        self.assertEqual(view["status"], "failed")
        self.assertEqual(view["error"]["code"], "ALL_SOURCES_FAILED")
        self.assertNotIn("results", view)

    def test_live_modules_only_run_when_live_is_set(self):
        job = scanner.ScanJob("jkl", "example.com", ["dns", "headers"], live=False)
        self.assertNotIn("headers", job.requested)
        job_live = scanner.ScanJob("mno", "example.com", ["dns", "headers"], live=True)
        self.assertIn("headers", job_live.requested)


class ReportTests(unittest.TestCase):
    def _view(self):
        return {
            "scan_id": "abc", "domain": "example.com", "status": "completed", "progress": 100,
            "modules": {"dns": {"status": "done", "count": 1}}, "live": False,
            "finished_at": "2026-11-13T10:00:00+00:00", "duration_seconds": 3.2,
            "results": {
                "domain_details": {"registrar": "<script>alert(1)</script>", "found": True},
                "dns": [{"type": "A", "value": "192.0.2.10", "ttl": 300, "source": "x"}],
                "subdomain_details": [{"name": "www.example.com", "first_seen": "2025", "source": "crt.sh"}],
                "certificates": [], "ssl": {"days_left": 5, "issuer": "CN=X"},
                "email_security": {"spf": None, "dmarc": None},
                "warnings": [],
            },
        }

    def test_html_escapes_registrar_text(self):
        html_text = report.render_html(self._view())
        self.assertNotIn("<script>alert(1)</script>", html_text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_text)

    def test_html_states_observations_and_sources(self):
        html_text = report.render_html(self._view())
        self.assertIn("expires in 5 day(s)", html_text)
        self.assertIn("No SPF record", html_text)
        self.assertIn("crt.sh", html_text)
        self.assertIn("passive sources only", html_text)

    def test_csv_has_header_and_rows(self):
        csv_text = report.render_csv(self._view())
        self.assertTrue(csv_text.splitlines()[0].startswith("section,type,value"))
        self.assertIn("dns,A,192.0.2.10", csv_text)
        self.assertIn("subdomain,name,www.example.com", csv_text)


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _request(self, method, path, body=None, host=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if host:
            request.add_header("Host", host)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read() or b"{}")

    def test_health(self):
        status, body = self._request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["engine"], "cybrot")

    def test_rejects_foreign_host_header(self):
        status, body = self._request("GET", "/api/health", host="attacker.example:8000")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "BAD_HOST")

    def test_invalid_domain_refused(self):
        status, body = self._request("POST", "/api/scans", {"domain": "127.0.0.1"})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "INVALID_DOMAIN")

    def test_active_scans_refused(self):
        status, body = self._request("POST", "/api/scans", {"domain": "example.com", "passive_only": False})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "ACTIVE_NOT_SUPPORTED")

    def test_live_checks_need_authorization(self):
        status, body = self._request("POST", "/api/scans", {"domain": "example.com", "live": True})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "AUTHORIZATION_REQUIRED")

    def test_unknown_scan_is_404(self):
        status, body = self._request("GET", "/api/scans/0123456789abcdef")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
