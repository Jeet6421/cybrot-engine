"""Report output: HTML, PDF (CYBROT template layout), CSV and JSON.

All formats are built from one list of sections, so they say the same things. Values are escaped for HTML
and guarded against spreadsheet formulas in CSV.
"""
import csv
import datetime as dt
import html
import io
import json

from . import VERSION, pdf

MODULE_LABELS = {
    "whois": "Registration (RDAP)",
    "dns": "DNS and email",
    "subdomains": "Subdomains (certificate logs)",
    "ssl": "Certificates (certificate logs)",
    "hosts": "Name resolution (DNS)",
    "threat": "Threat intelligence",
    "headers": "Security headers (live)",
}
VERDICT_LABELS = {
    "flagged": "Flagged by at least one provider",
    "mentioned": "Mentioned in threat reports, not confirmed malicious",
    "no_findings": "No flags from the providers that returned data",
    "no_data": "No record of this domain at the providers",
    "not_configured": "Not run: no API key set on the engine",
}


# ---- value helpers ----

def _e(value):
    return html.escape("" if value is None else str(value), quote=True)


def _v(value):
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    if value is None or value == "" or value == [] or value == {}:
        return "—"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    return str(value)


def _resolves_text(value):
    return {True: "Yes", False: "No"}.get(value, "Not checked")


def _csv_safe(value):
    """Stop spreadsheets from running a cell that starts with a formula character."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


# ---- observations: factual notes, not vulnerability findings ----

def observations(results, modules):
    items = []
    ssl = results.get("ssl") or {}
    if ssl.get("days_left") is not None and ssl["days_left"] < 30:
        items.append(f"The most recent certificate expires in {ssl['days_left']} day(s).")

    email = results.get("email_security") or {}
    if email:
        if not email.get("spf"):
            items.append("No SPF record was found at the domain root.")
        if not email.get("dmarc"):
            items.append("No DMARC record was found at _dmarc for this domain.")
        elif email.get("dmarc_policy") == "none":
            items.append("The DMARC policy is p=none, which monitors but does not block spoofed mail.")

    items.extend(results.get("dns_notes") or [])

    hosts = results.get("hosts") or {}
    if hosts.get("checked"):
        text = f"{hosts.get('resolving', 0)} of {hosts['checked']} checked name(s) resolve in DNS."
        text += " A resolving name does not show that a website answers there."
        if hosts.get("truncated"):
            text += " Only the first names found were checked."
        items.append(text)

    threat = results.get("threat_intel") or {}
    flags = []
    for provider in threat.get("providers") or []:
        if provider.get("malicious"):
            flags.append(
                f"{provider['provider']} reports {provider['malicious']} of "
                f"{provider.get('engines_total', 0)} engines flagging it as malicious"
            )
        if provider.get("suspicious"):
            flags.append(f"{provider['provider']} reports {provider['suspicious']} engine(s) as suspicious")
        if provider.get("pulses"):
            flags.append(f"{provider['provider']} lists the domain in {provider['pulses']} threat report(s)")
    if flags:
        items.append("Threat intelligence: " + "; ".join(flags) + ". Verify with the provider before acting on this.")

    if results.get("wildcard_certificates_seen"):
        items.append("Wildcard certificates were seen. This does not prove that DNS wildcard records exist.")

    failed = [name for name, info in (modules or {}).items() if info.get("status") == "failed"]
    if failed:
        labels = ", ".join(MODULE_LABELS.get(name, name) for name in failed)
        items.append(f"Some sources failed, so the picture is incomplete: {labels}.")
    return items


# ---- one shared list of sections ----
# A block is ("p", text) | ("note", text) | ("list", items) | ("kv", [(label, value)]) | ("table", headers, rows)

def _sources(results, live):
    rows = [
        ("RDAP registration data", "https://rdap.org/"),
        ("DNS records and email policy", "DNS over HTTPS: https://cloudflare-dns.com/dns-query, fallback https://dns.google/resolve"),
        ("Subdomains and certificates", "https://crt.sh/ (Certificate Transparency logs)"),
    ]
    if results.get("hosts"):
        rows.append(("Name resolution", "DNS over HTTPS, A records for each discovered name"))
    for provider in (results.get("threat_intel") or {}).get("providers") or []:
        rows.append((provider["provider"], provider["source"]))
    if live:
        rows.append(("Live checks", "Direct HTTPS and TLS connections, authorized scans only"))
    return rows


def _sections(view):
    results = view.get("results") or {}
    modules = view.get("modules") or {}
    live_results = results.get("live") or {}
    details = results.get("domain_details") or {}
    dns = results.get("dns") or []
    subs = results.get("subdomain_details") or []
    certs = results.get("certificates") or []
    ssl = results.get("ssl") or {}
    email = results.get("email_security") or {}
    hosts = results.get("hosts") or {}
    threat = results.get("threat_intel")
    is_live = bool(view.get("live"))
    generated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    obs = results.get("observations") or observations(results, modules)

    if threat is None:
        threat_label = "Not requested in this scan."
    else:
        threat_label = VERDICT_LABELS.get(threat.get("verdict"), str(threat.get("verdict")))

    summary = (
        f"{len(subs)} name(s) found in certificate logs. {hosts.get('resolving', 0)} of "
        f"{hosts.get('checked', 0)} checked name(s) resolve in DNS. {len(dns)} DNS record(s) and "
        f"{len(certs)} certificate(s) recorded."
    )

    module_rows = [
        [MODULE_LABELS.get(name, name), info.get("status"), info.get("count", "—"), info.get("message", "—")]
        for name, info in modules.items()
    ]

    sections = [
        ("Executive summary", [
            ("p", summary),
            ("p", f"Threat intelligence: {threat_label}"),
            ("p", "Scan mode: " + ("passive sources plus authorized live checks" if is_live else "passive sources only")),
            ("note", "Observations are factual notes drawn from the collected data. They are not vulnerability findings."),
            ("list", obs or ["No observations were raised by the collected data."]),
        ]),
        ("Target information", [
            ("kv", [
                ("Domain", view.get("domain")), ("Scan ID", view.get("scan_id")),
                ("Scan mode", "Live checks enabled" if is_live else "Passive only"),
                ("Finished (UTC)", view.get("finished_at")), ("Duration (seconds)", view.get("duration_seconds")),
                ("Engine version", VERSION), ("Report generated", generated),
            ]),
        ]),
        ("Collection methodology", [
            ("p", "Each module queries the sources listed below. Results are recorded with their source and the time of collection."),
            ("table", ["Source", "Address used"], _sources(results, is_live)),
            ("table", ["Module", "Status", "Items", "Note"], module_rows),
        ]),
        ("Domain registration", [
            ("kv", [
                ("Registered", details.get("found")), ("Registrar", details.get("registrar")),
                ("Created", details.get("created")), ("Expires", details.get("expires")),
                ("Last updated", details.get("last_updated")), ("Status", details.get("status")),
                ("Name servers", details.get("name_servers")), ("Source", details.get("source")),
            ]),
        ]),
        ("DNS and email authentication", [
            ("table", ["Type", "Value", "TTL", "Source"],
             [[r.get("type"), r.get("value"), r.get("ttl"), r.get("source")] for r in dns]),
            ("kv", [
                ("SPF", email.get("spf")), ("DMARC", email.get("dmarc")),
                ("DMARC policy", email.get("dmarc_policy")), ("DKIM", email.get("dkim")),
            ]),
        ]),
        ("Subdomains and name resolution", [
            ("p", "Names found in certificate transparency logs. A name in a certificate does not show that it "
                  "resolves. The DNS check below shows whether it does. Only authorized live checks contact these names."),
            ("kv", [
                ("Names found", len(subs)), ("Names checked", hosts.get("checked", 0)),
                ("Names that resolve in DNS", hosts.get("resolving", 0)),
                ("More names than the check limit", "Yes" if hosts.get("truncated") else "No"),
            ]),
            ("table", ["Name", "Resolves in DNS", "Addresses", "First seen in logs", "HTTP status"],
             [[s["name"], _resolves_text(s.get("resolves")), s.get("addresses") or [], s.get("first_seen"),
               s.get("http_status", "—")] for s in subs]),
        ]),
        ("SSL/TLS findings", [
            ("kv", [
                ("Issuer (latest certificate)", ssl.get("issuer")), ("Valid until", ssl.get("valid_until")),
                ("Days left", ssl.get("days_left")), ("Protocol", ssl.get("protocol")), ("Source", ssl.get("source")),
            ]),
            ("table", ["Issued", "Expires", "Issuer", "Names", "crt.sh ID"],
             [[c.get("not_before"), c.get("not_after"), c.get("issuer"), c.get("names", [])[:5], c.get("crt_sh_id")]
              for c in certs]),
        ]),
    ]

    if threat is None:
        threat_blocks = [("p", "Threat intelligence was not requested in this scan.")]
    else:
        rows = []
        for provider in threat.get("providers") or []:
            if provider.get("found") is False:
                rows.append([provider["provider"], "No record", "—", "—", "—", "—", "—", provider["source"]])
            else:
                rows.append([
                    provider["provider"], provider.get("malicious"), provider.get("suspicious"),
                    provider.get("harmless"), provider.get("undetected"), provider.get("pulses"),
                    provider.get("last_analysis"), provider["source"],
                ])
        threat_blocks = [
            ("kv", [("Verdict", threat_label), ("Checked (UTC)", threat.get("checked_at"))]),
            ("table", ["Provider", "Malicious", "Suspicious", "Harmless", "Undetected", "Threat reports",
                       "Last analysis", "Source"], rows),
            ("note", "Reputation data from third-party services. A flag is a lead to verify, not proof that "
                     "the domain is compromised."),
        ]
        if threat.get("errors"):
            threat_blocks.append(("list", threat["errors"]))
    sections.append(("Threat intelligence", threat_blocks))

    if is_live:
        tls = live_results.get("tls")
        headers = live_results.get("headers")
        probe_summary = live_results.get("hosts") or {}
        live_blocks = []
        if tls:
            live_blocks.append(("kv", [
                ("TLS protocol", tls.get("protocol")), ("Issuer", tls.get("issuer")),
                ("Valid until", tls.get("not_after")), ("Fingerprint (SHA-256)", tls.get("fingerprint_sha256")),
                ("Source", tls.get("source")),
            ]))
        elif live_results.get("tls_error"):
            live_blocks.append(("p", f"TLS check did not complete: {live_results['tls_error']}"))
        if headers:
            live_blocks.append(("kv", list(headers["headers"].items()) + [
                ("HTTP status", headers.get("status")), ("Redirect to", headers.get("redirect_to")),
                ("Source", headers.get("source")),
            ]))
        elif live_results.get("headers_error"):
            live_blocks.append(("p", f"Header check did not complete: {live_results['headers_error']}"))
        if probe_summary:
            live_blocks.append(("kv", [
                ("Names probed", probe_summary.get("probed")),
                ("Names answering over HTTPS", probe_summary.get("responding")),
                ("Probe limit", probe_summary.get("limit")), ("Source", probe_summary.get("source")),
            ]))
            probed = [s for s in subs if "verified_live" in s]
            live_blocks.append(("table", ["Name", "HTTP status", "Server", "Note"], [
                [s["name"], s.get("http_status"), s.get("server"), s.get("probe_error")] for s in probed
            ]))
        if not live_blocks:
            live_blocks.append(("p", "No live check produced results."))
        sections.append(("Live checks (authorized scan)", live_blocks))

    sections.append(("Evidence and sources", [
        ("table", ["Source", "Address used"], _sources(results, is_live)),
    ]))
    sections.append(("Limitations and disclaimer", [
        ("list", [
            "Results come from third-party public services and can be incomplete, delayed or out of date.",
            "Certificate transparency lists certificates that were issued. A name appearing there does not show "
            "that it resolves or hosts anything.",
            "No vulnerability is claimed in this report. A missing header or record is an observation to verify, "
            "not proof of a weakness.",
            "Scan only domains you own or are authorized to research. Third-party services have their own terms.",
        ]),
    ]))
    return sections, generated


# ---- HTML ----

def _html_rows(pairs):
    body = "".join(f"<tr><th>{_e(k)}</th><td>{_e(_v(v))}</td></tr>" for k, v in pairs)
    return f"<table>{body}</table>"


def _html_table(headers, rows):
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    if not rows:
        return (f"<table><thead><tr>{head}</tr></thead><tbody><tr><td colspan='{len(headers)}'>"
                "No data returned.</td></tr></tbody></table>")
    body = "".join("<tr>" + "".join(f"<td>{_e(_v(c))}</td>" for c in row) + "</tr>" for row in rows)
    return f"<div class='scroll'><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def _html_block(block):
    kind = block[0]
    if kind == "p":
        return f"<p>{_e(block[1])}</p>"
    if kind == "note":
        return f"<div class='note'>{_e(block[1])}</div>"
    if kind == "list":
        return "<ul>" + "".join(f"<li>{_e(item)}</li>" for item in block[1]) + "</ul>"
    if kind == "kv":
        return _html_rows(block[1])
    if kind == "table":
        return _html_table(block[1], block[2])
    return ""


HTML_CSS = """
:root { color-scheme: light; }
body { margin: 0; font: 14px/1.5 system-ui, Segoe UI, Roboto, sans-serif; color: #17202A; background: #fff; }
main { max-width: 960px; margin: 0 auto; padding: 32px 24px 64px; }
h1 { font-size: 26px; margin: 0 0 4px; } h2 { font-size: 18px; margin: 28px 0 8px; border-bottom: 1px solid #D5DBE3; padding-bottom: 4px; }
.meta { color: #55606E; margin-bottom: 16px; }
table { width: 100%; border-collapse: collapse; margin: 6px 0 10px; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid #E3E8EE; word-break: break-word; }
th { color: #3A4654; font-weight: 600; width: 32%; }
thead th { width: auto; background: #F4F6F9; }
.scroll { overflow-x: auto; }
.note { background: #F4F6F9; border-left: 3px solid #2F6FB0; padding: 10px 12px; margin: 10px 0; }
@media print { main { padding: 0; } h2 { break-after: avoid; } }
"""


def render_html(view):
    sections, generated = _sections(view)
    domain = view.get("domain", "")
    body = []
    for title, blocks in sections:
        body.append(f"<h2>{_e(title)}</h2>")
        body.extend(_html_block(block) for block in blocks)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CYBROT OSINT report: {_e(domain)}</title>
<style>{HTML_CSS}</style></head>
<body><main>
<h1>CYBROT OSINT report: {_e(domain)}</h1>
<div class="meta">Scan {_e(view.get('scan_id'))} · finished {_e(view.get('finished_at'))} · duration {_e(view.get('duration_seconds'))} s · engine {VERSION} · generated {generated}</div>
{''.join(body)}
</main></body></html>
"""


# ---- PDF ----

def render_pdf(view):
    sections, generated = _sections(view)
    domain = view.get("domain", "")
    doc = pdf.PdfDocument()
    doc.text(f"CYBROT OSINT report: {domain}", font="bold", size=18, gap_after=2)
    doc.text(f"Scan {view.get('scan_id')} · finished {view.get('finished_at')} · engine {VERSION}",
             font="mono", size=8, gap_after=10)
    for title, blocks in sections:
        doc.heading(title)
        for block in blocks:
            kind = block[0]
            if kind == "p":
                doc.text(block[1])
            elif kind == "note":
                doc.text(block[1], font="bold", size=9)
            elif kind == "list":
                for item in block[1]:
                    doc.text(f"- {item}", gap_after=2)
            elif kind == "kv":
                doc.table(None, [[k, _v(v)] for k, v in block[1]], ratios=[1, 2])
            elif kind == "table":
                doc.table(block[1], [[_v(c) for c in row] for row in block[2]])
    footer = f"CYBROT OSINT report · {domain} · scan {view.get('scan_id')} · generated {generated}"
    return doc.to_bytes(title=f"CYBROT OSINT report: {domain}", footer=footer)


# ---- CSV and JSON ----

def render_csv(view):
    results = view.get("results") or {}
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["section", "type", "value", "detail", "source", "timestamp"])
    details = results.get("domain_details") or {}
    for key in ("registrar", "created", "expires", "last_updated"):
        writer.writerow([_csv_safe(v) for v in ("registration", key, details.get(key) or "", "", details.get("source", ""), "")])
    for record in results.get("dns") or []:
        writer.writerow([_csv_safe(v) for v in ("dns", record["type"], record["value"], f"ttl={record['ttl']}", record["source"], "")])
    for item in results.get("subdomain_details") or []:
        detail = f"resolves={_resolves_text(item.get('resolves'))}; addresses={', '.join(item.get('addresses') or [])}"
        writer.writerow([_csv_safe(v) for v in ("subdomain", "name", item["name"], detail, item["source"], item["first_seen"] or "")])
    for cert in results.get("certificates") or []:
        writer.writerow([_csv_safe(v) for v in ("certificate", "issued", cert["not_after"] or "", cert["issuer"] or "", cert["source"], cert["not_before"] or "")])
    threat = results.get("threat_intel")
    if threat:
        writer.writerow([_csv_safe(v) for v in ("threat", "verdict", threat.get("verdict"), "", "", threat.get("checked_at") or "")])
        for provider in threat.get("providers") or []:
            detail = (f"malicious={_v(provider.get('malicious'))}; suspicious={_v(provider.get('suspicious'))}; "
                      f"pulses={_v(provider.get('pulses'))}")
            writer.writerow([_csv_safe(v) for v in ("threat", provider["provider"], "", detail, provider["source"], provider.get("last_analysis") or "")])
    for item in results.get("subdomain_details") or []:
        if "http_status" in item or "probe_error" in item:
            detail = f"status={_v(item.get('http_status'))}; server={_v(item.get('server'))}; error={_v(item.get('probe_error'))}"
            writer.writerow([_csv_safe(v) for v in ("live", "https", item["name"], detail, "Live HTTPS GET (authorized scan)", "")])
    return buffer.getvalue()


def render_json(view):
    return json.dumps(view, indent=2, default=str)
