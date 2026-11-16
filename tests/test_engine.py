"""Engine tests. Outside sources are replaced with fixtures, so these run without internet access.

Run from the engine folder:  python3 -m unittest discover -s tests -v
"""
import contextlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from cybrot_engine import collectors, net, pdf, report, scanner, server  # noqa: E402

CT_ENTRIES = [
    {"id": 9, "name_value": "www.example.com\napi.example.com", "issuer_name": "CN=Test CA",
     "not_before": "2025-01-01T00:00:00", "not_after": "2099-01-01T00:00:00",
     "entry_timestamp": "2025-01-02T00:00:00"},
]


def _resolve_all(names):
    return {n: {"resolves": True, "addresses": ["192.0.2.10"], "error": None} for n in names}


@contextlib.contextmanager
def offline(ct_error=False, ct_entries=None, threat=False):
    """Replace every outside source with a fixture. Threat intelligence is off unless a test asks for it."""
    patches = [
        mock.patch("cybrot_engine.collectors.ct_entries",
                   side_effect=net.NetError("crt.sh timed out.") if ct_error else None,
                   return_value=ct_entries if ct_entries is not None else CT_ENTRIES),
        mock.patch("cybrot_engine.collectors.rdap",
                   return_value={"found": True, "registrar": "Test Registrar", "created": "1995-01-01",
                                 "expires": "2030-01-01", "name_servers": ["ns1.example.net"],
                                 "source": collectors.RDAP_SOURCE}),
        mock.patch("cybrot_engine.collectors.dns_records",
                   return_value=[{"type": "A", "value": "192.0.2.10", "ttl": 300, "source": "x"}]),
        mock.patch("cybrot_engine.collectors.email_security",
                   return_value={"spf": None, "dmarc": None, "dmarc_policy": None, "dkim": "n/a", "source": "x"}),
        mock.patch("cybrot_engine.collectors.resolve_names", side_effect=_resolve_all),
    ]
    if not threat:
        patches.append(mock.patch("cybrot_engine.collectors.threat_intel",
                                  return_value={"verdict": "not_configured", "providers": [], "errors": [],
                                                "checked_at": None}))
    with contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        yield


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
        with self.assertRaises(net.TargetError):
            net.public_address("localhost")

    def test_live_probe_refuses_loopback_name(self):
        with self.assertRaises(net.TargetError):
            net.http_probe("localhost")


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

    def test_resolve_names_reports_addresses_and_unknowns(self):
        def fake_doh(name, rtype):
            if name == "www.example.com":
                return {"Answer": [{"type": 1, "data": "192.0.2.10"}]}
            if name == "gone.example.com":
                return {"Status": 3}  # NXDOMAIN: no answer section
            raise net.NetError("No DNS resolver answered.")

        with mock.patch("cybrot_engine.net.doh_query", side_effect=fake_doh):
            result = collectors.resolve_names(["www.example.com", "gone.example.com", "broken.example.com"])
        self.assertEqual(result["www.example.com"], {"resolves": True, "addresses": ["192.0.2.10"], "error": None})
        self.assertFalse(result["gone.example.com"]["resolves"])
        self.assertIsNone(result["broken.example.com"]["resolves"])


class ThreatTests(unittest.TestCase):
    VT_PAYLOAD = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 60, "undetected": 20},
        "reputation": -12, "last_analysis_date": 1767225600}}}

    def test_no_keys_means_not_configured_and_no_network(self):
        with mock.patch("cybrot_engine.net.fetch_json", side_effect=AssertionError("no request expected")):
            result = collectors.threat_intel("example.com", env={})
        self.assertEqual(result["verdict"], "not_configured")

    def test_keys_come_from_environment_only(self):
        keys = collectors.configured_threat_keys({"CYBROT_VT_API_KEY": "  abc  ", "CYBROT_OTX_API_KEY": ""})
        self.assertEqual(keys, {"virustotal": "abc"})

    def test_virustotal_is_called_with_key_header_and_parsed(self):
        with mock.patch("cybrot_engine.net.fetch_json", return_value=self.VT_PAYLOAD) as fetch:
            result = collectors.virustotal_domain("example.com", "KEY")
        self.assertEqual(fetch.call_args.kwargs["headers"], {"x-apikey": "KEY"})
        self.assertEqual(result["malicious"], 3)
        self.assertEqual(result["engines_total"], 84)
        self.assertIsInstance(result["last_analysis"], str)

    def test_flagged_verdict_and_key_never_in_output(self):
        def fake_fetch(url, **kwargs):
            if "virustotal" in url:
                return self.VT_PAYLOAD
            return {"pulse_info": {"count": 0}}

        env = {"CYBROT_VT_API_KEY": "SECRETKEY123", "CYBROT_OTX_API_KEY": "OTXSECRET"}
        with mock.patch("cybrot_engine.net.fetch_json", side_effect=fake_fetch):
            result = collectors.threat_intel("example.com", env=env)
        self.assertEqual(result["verdict"], "flagged")
        self.assertEqual(len(result["providers"]), 2)
        self.assertNotIn("SECRETKEY123", json.dumps(result))
        self.assertNotIn("OTXSECRET", json.dumps(result))

    def test_one_provider_failing_keeps_the_other(self):
        def fake_fetch(url, **kwargs):
            if "virustotal" in url:
                raise net.NetError("VirusTotal is down.")
            return {"pulse_info": {"count": 0}}

        with mock.patch("cybrot_engine.net.fetch_json", side_effect=fake_fetch):
            result = collectors.threat_intel("example.com", env={"CYBROT_VT_API_KEY": "a", "CYBROT_OTX_API_KEY": "b"})
        self.assertEqual(result["verdict"], "no_findings")
        self.assertEqual(len(result["errors"]), 1)

    def test_all_providers_failing_raises_so_module_fails(self):
        with mock.patch("cybrot_engine.net.fetch_json", side_effect=net.NetError("down")):
            with self.assertRaises(net.NetError):
                collectors.threat_intel("example.com", env={"CYBROT_VT_API_KEY": "a"})


class ScanJobTests(unittest.TestCase):
    def test_passive_scan_completes_with_real_shape(self):
        with offline():
            job = scanner.ScanJob("abc", "example.com", scanner.PASSIVE_MODULES)
            job.run()
        view = job.view()
        self.assertEqual(view["status"], "completed")
        self.assertEqual(view["progress"], 100)
        self.assertEqual(view["results"]["subdomains"], ["api.example.com", "www.example.com"])
        self.assertEqual(view["results"]["ssl"]["issuer"], "CN=Test CA")
        self.assertEqual(view["results"]["domain_details"]["registrar"], "Test Registrar")
        self.assertIsNone(view["results"]["ssl"]["protocol"])
        self.assertEqual(view["modules"]["subdomains"]["count"], 2)
        self.assertIn("finished_at", view)

    def test_hosts_check_marks_names_that_resolve(self):
        with offline():
            job = scanner.ScanJob("hst", "example.com", ["hosts"])  # hosts pulls in subdomains automatically
            job.run()
        view = job.view()
        self.assertIn("subdomains", view["modules"])
        self.assertEqual(view["results"]["hosts"]["resolving"], 2)
        www = next(d for d in view["results"]["subdomain_details"] if d["name"] == "www.example.com")
        self.assertEqual(www["addresses"], ["192.0.2.10"])
        self.assertIsNone(www.get("http_status"))  # passive scans never contact the names

    def test_threat_module_skipped_without_key_is_not_a_failure(self):
        with offline():
            job = scanner.ScanJob("thr", "example.com", ["dns", "threat"])
            job.run()
        view = job.view()
        self.assertEqual(view["status"], "completed")
        self.assertEqual(view["modules"]["threat"]["status"], "skipped")
        self.assertFalse(any("threat" in w for w in view["results"]["warnings"]))

    def test_threat_results_recorded_when_configured(self):
        fixture = {"verdict": "flagged", "errors": [], "checked_at": "2026-01-01T00:00:00+00:00",
                   "providers": [{"provider": "VirusTotal", "found": True, "malicious": 2, "suspicious": 0,
                                  "harmless": 50, "undetected": 30, "engines_total": 82, "source": "x"}]}
        with offline(), mock.patch("cybrot_engine.collectors.threat_intel", return_value=fixture):
            job = scanner.ScanJob("thc", "example.com", ["threat"])
            job.run()
        view = job.view()
        self.assertEqual(view["modules"]["threat"]["status"], "done")
        self.assertEqual(view["results"]["threat_intel"]["verdict"], "flagged")
        self.assertTrue(any("VirusTotal reports 2 of 82" in o for o in view["results"]["observations"]))

    def test_one_failed_source_keeps_the_rest(self):
        with offline(ct_error=True):
            job = scanner.ScanJob("def", "example.com", scanner.PASSIVE_MODULES)
            job.run()
        view = job.view()
        self.assertEqual(view["status"], "completed")
        self.assertEqual(view["modules"]["subdomains"]["status"], "failed")
        self.assertIn("crt.sh timed out", view["modules"]["subdomains"]["message"])
        self.assertEqual(view["modules"]["whois"]["status"], "done")
        self.assertTrue(any("subdomains" in w for w in view["results"]["warnings"]))

    def test_all_sources_failing_reports_failed_scan(self):
        with offline(ct_error=True), \
                mock.patch("cybrot_engine.collectors.rdap", side_effect=net.NetError("RDAP down.")), \
                mock.patch("cybrot_engine.collectors.dns_records", side_effect=net.NetError("DNS down.")):
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

    def test_live_host_probes_only_in_live_mode_and_record_errors(self):
        ct = [{"id": 9, "name_value": "www.example.com\napi.example.com", "issuer_name": "CN=T",
               "not_before": "2025-01-01T00:00:00", "not_after": "2099-01-01T00:00:00"}]

        def fake_probe(host, timeout=8):
            if host == "api.example.com":
                raise net.NetError("No HTTPS answer from api.example.com: timed out.")
            return {"host": host, "status": 200, "server": "nginx", "source": net.PROBE_SOURCE}

        with offline(ct_entries=ct), \
                mock.patch("cybrot_engine.net.http_probe", side_effect=fake_probe), \
                mock.patch("cybrot_engine.net.tls_certificate", side_effect=net.NetError("skip")), \
                mock.patch("cybrot_engine.net.http_headers", side_effect=net.NetError("skip")):
            job = scanner.ScanJob("lv1", "example.com", ["subdomains", "hosts"], live=True)
            job.run()
        results = job.view()["results"]
        self.assertEqual(results["live"]["hosts"]["probed"], 2)
        self.assertEqual(results["live"]["hosts"]["responding"], 1)
        www = next(d for d in results["subdomain_details"] if d["name"] == "www.example.com")
        self.assertEqual(www["http_status"], 200)
        self.assertTrue(www["verified_live"])
        api = next(d for d in results["subdomain_details"] if d["name"] == "api.example.com")
        self.assertFalse(api["verified_live"])
        self.assertIn("timed out", api["probe_error"])

    def test_no_live_probes_in_passive_mode(self):
        with offline(), mock.patch("cybrot_engine.net.http_probe") as probe:
            job = scanner.ScanJob("lv2", "example.com", ["subdomains", "hosts"], live=False)
            job.run()
        probe.assert_not_called()


class ReportTests(unittest.TestCase):
    def _view(self):
        return {
            "scan_id": "abc", "domain": "example.com", "status": "completed", "progress": 100,
            "modules": {"dns": {"status": "done", "count": 1}, "threat": {"status": "skipped"}},
            "live": False, "finished_at": "2026-11-13T10:00:00+00:00", "duration_seconds": 3.2,
            "results": {
                "domain_details": {"registrar": "<script>alert(1)</script>", "found": True},
                "dns": [{"type": "A", "value": "192.0.2.10", "ttl": 300, "source": "x"}],
                "subdomain_details": [{"name": "www.example.com", "first_seen": "2025", "source": "crt.sh",
                                       "resolves": True, "addresses": ["192.0.2.10"]}],
                "hosts": {"checked": 1, "resolving": 1, "truncated": False},
                "certificates": [], "ssl": {"days_left": 5, "issuer": "CN=X"},
                "email_security": {"spf": None, "dmarc": None},
                "threat_intel": {"verdict": "flagged", "errors": [], "checked_at": "2026-01-01T00:00:00+00:00",
                                 "providers": [{"provider": "VirusTotal", "found": True, "malicious": 2,
                                                "suspicious": 0, "harmless": 50, "undetected": 30,
                                                "engines_total": 82, "source": "VirusTotal domain report"}]},
                "warnings": [],
            },
        }

    def test_html_escapes_registrar_text(self):
        html_text = report.render_html(self._view())
        self.assertNotIn("<script>alert(1)</script>", html_text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_text)

    def test_html_includes_threat_hosts_and_observations(self):
        html_text = report.render_html(self._view())
        self.assertIn("Threat intelligence", html_text)
        self.assertIn("Flagged by at least one provider", html_text)
        self.assertIn("expires in 5 day(s)", html_text)
        self.assertIn("No SPF record", html_text)
        self.assertIn("Names that resolve in DNS", html_text)
        self.assertIn("passive sources only", html_text)

    def test_csv_has_header_and_rows(self):
        csv_text = report.render_csv(self._view())
        self.assertTrue(csv_text.splitlines()[0].startswith("section,type,value"))
        self.assertIn("dns,A,192.0.2.10", csv_text)
        self.assertIn("subdomain,name,www.example.com", csv_text)
        self.assertIn("threat,verdict,flagged", csv_text)

    def test_csv_cells_cannot_start_formulas(self):
        view = self._view()
        view["results"]["dns"] = [{"type": "TXT", "value": "=HYPERLINK(\"http://x\")", "ttl": 1, "source": "x"}]
        csv_text = report.render_csv(view)
        self.assertIn("'=HYPERLINK", csv_text)
        self.assertNotIn(",=HYPERLINK", csv_text)

    def test_json_and_html_never_contain_api_keys(self):
        def fake_fetch(url, **kwargs):
            if "virustotal" in url:
                return ThreatTests.VT_PAYLOAD
            return {"pulse_info": {"count": 0}}

        env = {"CYBROT_VT_API_KEY": "SECRETKEY123", "CYBROT_OTX_API_KEY": "OTXSECRET"}
        with offline(threat=True), mock.patch("cybrot_engine.net.fetch_json", side_effect=fake_fetch), \
                mock.patch.dict("os.environ", env, clear=False):
            job = scanner.ScanJob("sec", "example.com", ["threat"])
            job.run()
        view = job.view()
        self.assertEqual(view["results"]["threat_intel"]["verdict"], "flagged")
        for output in (report.render_json(view), report.render_html(view), report.render_csv(view)):
            self.assertNotIn("SECRETKEY123", output)
            self.assertNotIn("OTXSECRET", output)


class PdfTests(unittest.TestCase):
    def _pdf(self):
        view = ReportTests()._view()
        return report.render_pdf(view)

    def test_structure_and_xref_offsets(self):
        data = self._pdf()
        self.assertTrue(data.startswith(b"%PDF-1.4"))
        self.assertTrue(data.rstrip().endswith(b"%%EOF"))
        xref_at = int(re.search(rb"startxref\n(\d+)\n%%EOF", data).group(1))
        self.assertTrue(data[xref_at:].startswith(b"xref"))
        entries = re.findall(rb"(\d{10}) 00000 n \n", data)
        self.assertGreater(len(entries), 5)
        for raw in entries:
            offset = int(raw)
            self.assertRegex(data[offset:offset + 12].decode("latin-1"), r"^\d+ 0 obj")

    def test_header_and_footer_on_every_page_and_no_watermark(self):
        data = self._pdf()
        pages = int(re.search(rb"/Count (\d+)", data).group(1))
        self.assertGreaterEqual(pages, 1)
        self.assertEqual(data.count(b"/IM1 Do"), pages)  # the template icon is drawn in the header of every page
        self.assertNotIn(b"/SMask", data)  # no transparency layer, so no watermark
        self.assertNotIn(b"/GS1", data)
        self.assertEqual(data.count(b"support@cybrot.com"), pages)  # template contact line in every footer
        self.assertIn(b"CYBROT", data)

    def test_icon_is_an_rgb_png_embedded_without_recompression(self):
        from cybrot_engine import brand
        width, height, idat = pdf.icon_png_info(brand.icon_png_bytes())
        self.assertEqual((width, height), (135, 202))
        self.assertGreater(len(idat), 1000)


    def test_text_is_escaped(self):
        self.assertEqual(pdf._literal("a (b) \\ c"), b"(a \\(b\\) \\\\ c)")

    def test_qpdf_accepts_the_file_when_available(self):
        if not shutil.which("qpdf"):
            self.skipTest("qpdf is not installed")
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as handle:
            handle.write(self._pdf())
        result = subprocess.run(["qpdf", "--check", handle.name], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


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

    def tearDown(self):
        with server._jobs_lock:
            server._jobs.pop("0123456789abcdef", None)

    def _request(self, method, path, body=None, host=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if host:
            request.add_header("Host", host)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.headers.get("Content-Type"), response.read()
        except urllib.error.HTTPError as err:
            return err.code, err.headers.get("Content-Type"), err.read()

    def _json(self, method, path, body=None, host=None):
        status, _, raw = self._request(method, path, body, host)
        return status, json.loads(raw or b"{}")

    def test_health(self):
        status, body = self._json("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["engine"], "cybrot")
        self.assertEqual(body["version"], "0.3.3")

    def test_rejects_foreign_host_header(self):
        status, body = self._json("GET", "/api/health", host="attacker.example:8000")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "BAD_HOST")

    def test_invalid_domain_refused(self):
        status, body = self._json("POST", "/api/scans", {"domain": "127.0.0.1"})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "INVALID_DOMAIN")

    def test_active_scans_refused(self):
        status, body = self._json("POST", "/api/scans", {"domain": "example.com", "passive_only": False})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "ACTIVE_NOT_SUPPORTED")

    def test_live_checks_need_authorization(self):
        status, body = self._json("POST", "/api/scans", {"domain": "example.com", "live": True})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "AUTHORIZATION_REQUIRED")

    def test_unknown_scan_is_404(self):
        status, body = self._json("GET", "/api/scans/0123456789abcdef")
        self.assertEqual(status, 404)

    def test_pdf_report_refused_until_completed_then_served(self):
        job = scanner.ScanJob("0123456789abcdef", "example.com", ["dns"])
        with server._jobs_lock:
            server._jobs["0123456789abcdef"] = job
        status, body = self._json("GET", "/api/scans/0123456789abcdef/report.pdf")
        self.assertEqual(status, 409)
        with offline():
            job.run()
        status, content_type, raw = self._request("GET", "/api/scans/0123456789abcdef/report.pdf")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/pdf")
        self.assertTrue(raw.startswith(b"%PDF-1.4"))

    def test_other_report_formats_still_served(self):
        job = scanner.ScanJob("0123456789abcdef", "example.com", ["dns"])
        with server._jobs_lock:
            server._jobs["0123456789abcdef"] = job
        with offline():
            job.run()
        status, content_type, raw = self._request("GET", "/api/scans/0123456789abcdef/report.csv")
        self.assertEqual(status, 200)
        self.assertIn(b"section,type,value", raw)
        status, content_type, raw = self._request("GET", "/api/scans/0123456789abcdef/report.html")
        self.assertEqual(status, 200)
        self.assertIn(b"CYBROT OSINT report", raw)


if __name__ == "__main__":
    unittest.main()
