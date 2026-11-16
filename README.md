# CYBROT OSINT local engine (v0.3.3)

The engine runs on your own computer. The CYBROT browser extension sends it scan requests on `http://127.0.0.1:8000`. It collects public registration data, DNS records, name resolution, certificate details and threat-intelligence reputation for a domain, then produces HTML, PDF, CSV and JSON reports.

## What it collects

| Module | Source | Passive? |
| --- | --- | --- |
| `whois` (registration) | RDAP via rdap.org | Yes |
| `dns` (records, SPF, DMARC) | DNS over HTTPS (Cloudflare, Google as fallback) | Yes |
| `subdomains` | Certificate Transparency logs via crt.sh | Yes |
| `ssl` (certificates) | Certificate Transparency logs via crt.sh | Yes |
| `hosts` (name resolution) | DNS over HTTPS, one A-record query per discovered name (up to 100) | Yes |
| `threat` (threat intelligence) | VirusTotal and AlienVault OTX, only if you set an API key | Yes |
| `headers` (security headers) | One direct HTTPS request to the target | **No, live check** |
| Live TLS handshake (inside `ssl`) | One direct TLS connection to the target | **No, live check** |
| Live HTTPS probe (inside `hosts`) | One HTTPS request to each resolving discovered name (up to 25) | **No, live check** |

Passive is the default. The extension uses only passive modules.

Resolving in DNS is not the same as serving a website. The `hosts` module only asks whether a name has an IPv4 address. The live probe is the only step that connects to a name, and it runs only for authorized scans.

## Threat intelligence keys

Threat intelligence needs an API key from the provider. Keys are read from environment variables on the engine's computer. They are never sent to the extension and never appear in reports.

| Provider | Variable | Get a key |
| --- | --- | --- |
| VirusTotal | `CYBROT_VT_API_KEY` | virustotal.com (free account) |
| AlienVault OTX | `CYBROT_OTX_API_KEY` | otx.alienvault.com (free account) |

Without a key the `threat` module shows as "skipped". The scan still works. Set a key in PowerShell before starting the engine, in the same window:

```powershell
$env:CYBROT_VT_API_KEY = "your-key-here"
py -m cybrot_engine
```

When the engine starts, it prints which providers are configured. It never prints the keys.

## Requirements

- Python 3.8 or newer. No third-party packages are needed.
- Internet access on the machine running the engine. The engine needs outside sources, and it will report "Could not reach ..." if it can't get them.

## Run it

Open a terminal in this folder (the one that contains `cybrot_engine`).

Windows PowerShell:

```powershell
py -m cybrot_engine
```

Mac and Linux:

```bash
python3 -m cybrot_engine
```

It listens only on `127.0.0.1:8000`. Leave the window open while you scan. To change the port, add `--port 8001`, then update `engineUrl` in the extension's `config.js` and the host permission in `manifest.json` to match.

Check it works: open http://127.0.0.1:8000/api/health in a browser. You should see `"engine": "cybrot"`.

## Live checks

Live checks connect to the domain and to up to 25 names found for it. They run only when the request includes both `"live": true` and `"authorized": true`. Use them only on domains and names you own or are authorized to test. The engine refuses addresses that are not public (loopback, private and link-local).

## Reports

After a scan completes, download a report from the extension, or open these in your browser (replace `SCAN_ID` with the scan ID):

- `http://127.0.0.1:8000/api/scans/SCAN_ID/report.pdf`: A4 PDF laid out to the CYBROT template: header with the logo and name, contact footer, and page numbers.
- `http://127.0.0.1:8000/api/scans/SCAN_ID/report.html`: opens in any browser.
- `http://127.0.0.1:8000/api/scans/SCAN_ID/report.csv`
- `http://127.0.0.1:8000/api/scans/SCAN_ID/report.json`

Every finding in a report lists its source and collection time. The report separates observations from vulnerabilities. A missing SPF record, for example, is an observation to check, not a proven weakness.

## API (used by the extension)

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/health` | Engine check |
| POST | `/api/scans` | Body: `{"domain": "example.com", "modules": ["whois","dns","subdomains","ssl","hosts","threat"], "passive_only": true}`. Optional `"live"` and `"authorized"`, both `true` for live checks. Returns `202` with `scan_id`. |
| GET | `/api/scans/{id}` | Status, progress, module states, and results when completed |
| POST | `/api/scans/{id}/cancel` | Stops the scan after the current module |
| GET | `/api/scans/{id}/report.html`, `.pdf`, `.csv`, `.json` | Available once the scan has completed |

Errors use `{"error": {"code": "...", "message": "..."}}`. Requests must use the `127.0.0.1` or `localhost` host name. At most two scans run at once. Reports return `409` until the scan completes.

## Limits in this version

- Results depend on the outside sources. crt.sh is sometimes slow or unavailable, and then the subdomain and certificate modules fail while the others still run.
- The `hosts` check uses IPv4 (A) records only, so IPv6-only names show as not resolving.
- Only the first 100 discovered names are checked in DNS, and only the first 25 resolving names are probed over HTTPS.
- Live checks look up each address once to block private and local addresses. The request itself is made separately, so a fast DNS change could in theory point it elsewhere. Treat this as a known limit for now.
- The TLS grade is not calculated, so the report shows no grade.
- Scans are kept in memory and are lost when the engine stops.
- Extension-to-engine authentication is not in this version. The next step adds a pairing code and token.
- DKIM is not checked, because it needs a selector name.
- The PDF uses standard fonts (Helvetica and Courier), so non-Latin text in names or issuers may show as `?`.

## Tests

From this folder:

```bash
python3 -m unittest discover -s tests -v
```

The tests use simulated responses, so they run without internet access. They do not prove that the real sources return the expected data. Test a scan against a domain you own to confirm the real output. The PDF test also runs `qpdf --check` when qpdf is installed.

## Legal and ethical use

Scan only domains you own or have permission to research. The passive sources are third-party services with their own terms, and a scan sends requests to them on your behalf. Do not use live checks against anything you are not authorized to test.
