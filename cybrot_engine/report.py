"""Report output: HTML (print to PDF from a browser), CSV and JSON. Every value is escaped or encoded."""
import csv
import datetime as dt
import html
import io
import json

from . import VERSION


def _e(value):
    return html.escape("" if value is None else str(value), quote=True)


def _rows(pairs):
    body = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v) if v not in (None, '', []) else '—'}</td></tr>" for k, v in pairs)
    return f"<table>{body}</table>"


def _table(headers, rows):
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    if not rows:
        return f"<table><thead><tr>{head}</tr></thead><tbody><tr><td colspan='{len(headers)}'>No data returned.</td></tr></tbody></table>"
    body = "".join("<tr>" + "".join(f"<td>{_e(c)}</td>" for c in row) + "</tr>" for row in rows)
    return f"<div class='scroll'><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def observations(view):
    """Factual observations drawn from the collected data. These are not vulnerability findings."""
    results = view.get("results") or {}
    items = []
    ssl = results.get("ssl") or {}
    if ssl.get("days_left") is not None and ssl["days_left"] < 30:
        items.append(f"The most recent certificate expires in {ssl['days_left']} day(s).")
    email = results.get("email_security") or {}
    if not email.get("spf"):
        items.append("No SPF record was found at the domain root.")
    if not email.get("dmarc"):
        items.append("No DMARC record was found at _dmarc for this domain.")
    elif email.get("dmarc_policy") == "none":
        items.append("The DMARC policy is p=none, which monitors but does not block spoofed mail.")
    items.extend(results.get("dns_notes") or [])
    if results.get("wildcard_certificates_seen"):
        items.append("Wildcard certificates were seen. This does not prove that DNS wildcard records exist.")
    failed = [name for name, info in (view.get("modules") or {}).items() if info.get("status") == "failed"]
    if failed:
        items.append("Some sources failed, so the picture is incomplete: " + ", ".join(failed) + ".")
    return items


def render_html(view):
    results = view.get("results") or {}
    domain = view.get("domain", "")
    details = results.get("domain_details") or {}
    dns = results.get("dns") or []
    subs = results.get("subdomain_details") or []
    certs = results.get("certificates") or []
    ssl = results.get("ssl") or {}
    email = results.get("email_security") or {}
    live = results.get("live") or {}
    modules = view.get("modules") or {}
    generated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    module_rows = [
        (name, info.get("status"), info.get("count", ""), info.get("message", ""))
        for name, info in modules.items()
    ]
    obs = observations(view)
    obs_html = "".join(f"<li>{_e(item)}</li>" for item in obs) or "<li>No observations were raised by the collected data.</li>"

    live_html = ""
    if view.get("live"):
        tls = live.get("tls")
        headers = live.get("headers")
        live_html = "<h2>Live checks (authorized scan)</h2>"
        if tls:
            live_html += "<h3>TLS handshake</h3>" + _rows([
                ("Protocol", tls.get("protocol")), ("Issuer", tls.get("issuer")),
                ("Valid until", tls.get("not_after")), ("Fingerprint (SHA-256)", tls.get("fingerprint_sha256")),
                ("Source", tls.get("source")),
            ])
        elif live.get("tls_error"):
            live_html += f"<p>TLS check did not complete: {_e(live['tls_error'])}</p>"
        if headers:
            live_html += "<h3>Security headers</h3>" + _rows(
                [(name, value) for name, value in headers["headers"].items()]
                + [("HTTP status", headers.get("status")), ("Redirect to", headers.get("redirect_to")),
                   ("Source", headers.get("source"))]
            )
        elif live.get("headers_error"):
            live_html += f"<p>Header check did not complete: {_e(live['headers_error'])}</p>"

    sources = [
        ("RDAP registration data", "https://rdap.org/"),
        ("DNS records", "https://cloudflare-dns.com/dns-query and https://dns.google/resolve"),
        ("Subdomains and certificates", "https://crt.sh/ (Certificate Transparency logs)"),
    ]
    if view.get("live"):
        sources.append(("Live checks", "Direct connection to the target, only for authorized scans"))

    css = """
    :root { color-scheme: light; }
    body { margin: 0; font: 14px/1.5 system-ui, Segoe UI, Roboto, sans-serif; color: #17202A; background: #fff; }
    main { max-width: 960px; margin: 0 auto; padding: 32px 24px 64px; }
    h1 { font-size: 26px; margin: 0 0 4px; } h2 { font-size: 18px; margin: 28px 0 8px; border-bottom: 1px solid #D5DBE3; padding-bottom: 4px; }
    h3 { font-size: 15px; margin: 16px 0 6px; }
    .meta { color: #55606E; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; margin: 6px 0 10px; }
    th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid #E3E8EE; word-break: break-word; }
    th { color: #3A4654; font-weight: 600; width: 32%; }
    thead th { width: auto; background: #F4F6F9; }
    .scroll { overflow-x: auto; }
    .note { background: #F4F6F9; border-left: 3px solid #2F6FB0; padding: 10px 12px; margin: 10px 0; }
    code { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
    @media print { main { padding: 0; } h2 { break-after: avoid; } table { break-inside: auto; } }
    """

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CYBROT OSINT report: {_e(domain)}</title>
<style>{css}</style></head>
<body><main>
<h1>CYBROT OSINT report: {_e(domain)}</h1>
<div class="meta">Scan {_e(view.get('scan_id'))} · finished {_e(view.get('finished_at'))} · duration {_e(view.get('duration_seconds'))} s · engine {VERSION} · generated {generated}</div>

<h2>Executive summary</h2>
<p>{len(subs)} subdomain name(s) discovered in certificate logs, {len(dns)} DNS record(s), {len(certs)} certificate(s) recorded.
Scan mode: {'passive sources plus authorized live checks' if view.get('live') else 'passive sources only'}.</p>
<div class="note"><strong>Observations</strong> are factual notes from the data, not vulnerability findings.</div>
<ul>{obs_html}</ul>

<h2>Target information</h2>
{_rows([('Domain', domain), ('Scan mode', 'Live checks enabled' if view.get('live') else 'Passive only')])}

<h2>Collection methodology</h2>
<p>Each module queries the public sources below. Results are recorded with the source and the time of collection.
Discovered subdomains are not checked for live hosts.</p>
{_table(['Source', 'Address used'], sources)}
{_table(['Module', 'Status', 'Items', 'Note'], module_rows)}

<h2>Domain intelligence (registration)</h2>
{_rows([
    ('Registered', details.get('found')), ('Registrar', details.get('registrar')),
    ('Created', details.get('created')), ('Expires', details.get('expires')),
    ('Last updated', details.get('last_updated')),
    ('Status', ', '.join(details.get('status') or []) or None),
    ('Name servers', ', '.join(details.get('name_servers') or []) or None),
    ('Source', details.get('source')),
])}

<h2>DNS findings</h2>
{_table(['Type', 'Value', 'TTL', 'Source'], [(r['type'], r['value'], r['ttl'], r['source']) for r in dns])}
<h3>Email authentication</h3>
{_rows([
    ('SPF', email.get('spf')), ('DMARC', email.get('dmarc')),
    ('DMARC policy', email.get('dmarc_policy')), ('DKIM', email.get('dkim')),
])}

<h2>Subdomain intelligence</h2>
<p>Names found in certificate transparency logs. These are discovered, not verified as live hosts.</p>
{_table(['Name', 'First seen in logs', 'Source'], [(s['name'], s['first_seen'], s['source']) for s in subs])}

<h2>SSL/TLS findings</h2>
{_rows([
    ('Issuer (latest certificate)', ssl.get('issuer')), ('Valid until', ssl.get('valid_until')),
    ('Days left', ssl.get('days_left')), ('Protocol', ssl.get('protocol')), ('Source', ssl.get('source')),
])}
{_table(['Issued', 'Expires', 'Issuer', 'Names', 'crt.sh ID'],
        [(c['not_before'], c['not_after'], c['issuer'], ', '.join(c['names'][:5]), c['crt_sh_id']) for c in certs])}

{live_html}

<h2>Evidence and sources</h2>
<ul>{''.join(f'<li>{_e(name)}: {_e(addr)}</li>' for name, addr in sources)}</ul>

<h2>Limitations and disclaimer</h2>
<ul>
<li>Results come from third-party public services and can be incomplete, delayed or out of date.</li>
<li>Certificate transparency lists certificates that were issued. A name appearing there does not show that it resolves or hosts anything.</li>
<li>No vulnerability is claimed in this report. A missing header or record is an observation to verify, not proof of a weakness.</li>
<li>Scan only domains you own or are authorized to research. Third-party services have their own terms.</li>
</ul>
</main></body></html>
"""


def render_csv(view):
    results = view.get("results") or {}
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["section", "type", "value", "detail", "source", "timestamp"])
    details = results.get("domain_details") or {}
    for key in ("registrar", "created", "expires", "last_updated"):
        writer.writerow(["registration", key, details.get(key) or "", "", details.get("source", ""), ""])
    for record in results.get("dns") or []:
        writer.writerow(["dns", record["type"], record["value"], f"ttl={record['ttl']}", record["source"], ""])
    for item in results.get("subdomain_details") or []:
        writer.writerow(["subdomain", "name", item["name"], "discovered, not verified live", item["source"], item["first_seen"] or ""])
    for cert in results.get("certificates") or []:
        writer.writerow(["certificate", "issued", cert["not_after"] or "", cert["issuer"] or "", cert["source"], cert["not_before"] or ""])
    return buffer.getvalue()


def render_json(view):
    return json.dumps(view, indent=2, default=str)
