# CYBROT OSINT local engine (v0.2.0)

The engine runs on your own computer. The CYBROT browser extension sends it scan requests on `http://127.0.0.1:8000`. It collects public registration data, DNS records, subdomains from certificate logs and certificate details, then produces HTML, CSV and JSON reports.

## What it collects

| Module | Source | Passive? |
| --- | --- | --- |
| `whois` (registration) | RDAP via rdap.org | Yes |
| `dns` (records, SPF, DMARC) | DNS over HTTPS (Cloudflare, Google as fallback) | Yes |
| `subdomains` | Certificate Transparency logs via crt.sh | Yes |
| `ssl` (certificates) | Certificate Transparency logs via crt.sh | Yes |
| `headers` (security headers) | One direct HTTPS request to the target | **No, live check** |
| TLS handshake (inside `ssl`) | One direct TLS connection to the target | **No, live check** |

Passive is the default. The extension uses only passive modules.

Discovered subdomains are names seen in certificates. They are not checked for live hosts. A certificate listing a name does not prove that the name resolves.

Live checks connect directly to the target domain. They run only when the request includes both `"live": true` and `"authorized": true`. Use them only on domains you own or are authorized to test.

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

## Reports

After a scan completes, open these in your browser (replace `SCAN_ID` with the scan ID shown in the extension or the engine's API response):

- `http://127.0.0.1:8000/api/scans/SCAN_ID/report.html`: print from the browser (Ctrl+P, "Save as PDF") for a PDF.
- `http://127.0.0.1:8000/api/scans/SCAN_ID/report.csv`
- `http://127.0.0.1:8000/api/scans/SCAN_ID/report.json`

Every finding in a report lists its source and collection time. The report separates observations from vulnerabilities. A missing SPF record, for example, is an observation to check, not a proven weakness.

## API (used by the extension)

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/health` | Engine check |
| POST | `/api/scans` | Body: `{"domain": "example.com", "modules": ["whois","dns","subdomains","ssl"], "passive_only": true}`. Optional `"live"` and `"authorized"`, both `true` for live checks. Returns `202` with `scan_id`. |
| GET | `/api/scans/{id}` | Status, progress, module states, and results when completed |
| POST | `/api/scans/{id}/cancel` | Stops the scan after the current module |
| GET | `/api/scans/{id}/report.html`, `.csv`, `.json` | Available once the scan has completed |

Errors use `{"error": {"code": "...", "message": "..."}}`. Requests must use the `127.0.0.1` or `localhost` host name. At most two scans run at once.

## Limits in this version

- Results depend on the outside sources. crt.sh is sometimes slow or unavailable, and then the subdomain and certificate modules fail while the others still run.
- The engine does not check whether discovered subdomains are live.
- The TLS grade is not calculated, so the report shows no grade.
- Live checks look up the address once to block private and local addresses. The request itself is made separately, so a fast DNS change could in theory point it elsewhere. Treat this as a known limit for now.
- Scans are kept in memory and are lost when the engine stops.
- Extension-to-engine authentication is not in this version. The next step adds a pairing code and token.
- DKIM is not checked, because it needs a selector name.

## Tests

From this folder:

```bash
python3 -m unittest discover -s tests -v
```

The tests use simulated responses, so they run without internet access. They do not prove that the real sources return the expected data. Test a scan against a domain you own to confirm the real output.

## Legal and ethical use

Scan only domains you own or have permission to research. The passive sources are third-party services with their own terms, and a scan sends requests to them on your behalf. Do not use live checks against anything you are not authorized to test.
