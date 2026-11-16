"""Network helpers. Every outbound request the engine makes goes through this file."""
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "CYBROT-OSINT/0.3 (local engine; passive by default)"
PROBE_SOURCE = "Live HTTPS GET, one request per name, no redirects (authorized scan)"
MAX_BYTES = 2_000_000
DOH_ENDPOINTS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA"}
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


class NetError(Exception):
    """A readable error about an outside source or a failed check."""


class TargetError(NetError):
    """The target was refused before any request was made."""


def normalize_domain(raw):
    """Accept 'example.com', 'https://www.example.com/x' and return a bare lowercase hostname."""
    text = str(raw or "").strip().lower()
    if "://" in text:
        text = urllib.parse.urlsplit(text).hostname or ""
    text = text.split("/")[0].rstrip(".")
    if not DOMAIN_RE.match(text):
        raise TargetError(f"'{raw}' is not a valid domain name. Enter a name such as example.com.")
    return text


def fetch_json(url, timeout=15, accept="application/json", allow_404=True, headers=None):
    request_headers = {"User-Agent": USER_AGENT, "Accept": accept, **(headers or {})}
    request = urllib.request.Request(url, headers=request_headers)
    host = urllib.parse.urlsplit(url).netloc
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as err:
        if err.code == 404 and allow_404:
            return None
        raise NetError(f"{host} answered HTTP {err.code}.")
    except (urllib.error.URLError, OSError) as err:
        reason = getattr(err, "reason", err)
        raise NetError(f"Could not reach {host}: {reason}.")
    if len(body) > MAX_BYTES:
        raise NetError(f"{host} sent more data than the engine accepts.")
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        raise NetError(f"{host} did not return JSON.")


def doh_query(name, rtype):
    """Ask a public DNS-over-HTTPS resolver. Tries the second resolver if the first fails."""
    query = urllib.parse.urlencode({"name": name, "type": rtype})
    last_error = NetError("No DNS resolver answered.")
    for endpoint in DOH_ENDPOINTS:
        try:
            data = fetch_json(f"{endpoint}?{query}", accept="application/dns-json", allow_404=False)
        except NetError as err:
            last_error = err
            continue
        if isinstance(data, dict):
            return data
        last_error = NetError("The DNS resolver returned an unexpected answer.")
    raise last_error


def public_address(host):
    """Resolve a host and refuse it unless every address is public (blocks loopback, private and link-local)."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as err:
        raise NetError(f"Could not resolve {host}: {err}.")
    addresses = []
    for info in infos:
        address = info[4][0]
        if not ipaddress.ip_address(address).is_global:
            raise TargetError(f"{host} resolves to a non-public address, so the engine will not contact it.")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise NetError(f"{host} has no address to contact.")
    return addresses[0]


def _name_text(rdns):
    return ", ".join(f"{key}={value}" for rdn in rdns for key, value in rdn)


def tls_certificate(host, timeout=10):
    """Live check: one TLS handshake to the target. Only runs for authorized scans."""
    ip = public_address(host)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                info = tls.getpeercert()
                der = tls.getpeercert(binary_form=True)
                version = tls.version()
    except (OSError, ssl.SSLError) as err:
        raise NetError(f"TLS handshake with {host} failed: {err}.")
    not_after = ssl.cert_time_to_seconds(info["notAfter"])
    not_before = ssl.cert_time_to_seconds(info["notBefore"])
    return {
        "subject": _name_text(info.get("subject", ())),
        "issuer": _name_text(info.get("issuer", ())),
        "san": [value for kind, value in info.get("subjectAltName", ()) if kind == "DNS"],
        "not_before": _iso(not_before),
        "not_after": _iso(not_after),
        "protocol": version,
        "fingerprint_sha256": ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest()),
        "source": "Live TLS handshake (authorized scan)",
    }


def _iso(timestamp):
    import datetime as dt

    return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # report the redirect instead of following it


def http_headers(host, timeout=10):
    """Live check: one GET to the root page, no redirects followed, reading only security headers."""
    public_address(host)
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(f"https://{host}/", headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=timeout) as response:
            status, headers = response.status, response.headers
    except urllib.error.HTTPError as err:
        status, headers = err.code, err.headers
    except (urllib.error.URLError, OSError) as err:
        raise NetError(f"Could not fetch https://{host}/: {getattr(err, 'reason', err)}.")
    return {
        "status": status,
        "redirect_to": headers.get("Location"),
        "headers": {name: headers.get(name) for name in SECURITY_HEADERS},
        "source": "Live HTTP GET, one request, no redirects (authorized scan)",
    }


def http_probe(host, timeout=8):
    """Live check for one discovered name: one GET over HTTPS, no redirects followed, status and Server header only."""
    public_address(host)  # raises TargetError for loopback, private or link-local addresses
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(f"https://{host}/", headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=timeout) as response:
            status, server = response.status, response.headers.get("Server")
    except urllib.error.HTTPError as err:
        status, server = err.code, err.headers.get("Server")
    except (urllib.error.URLError, OSError) as err:
        raise NetError(f"No HTTPS answer from {host}: {getattr(err, 'reason', err)}.")
    return {"host": host, "status": status, "server": server, "source": PROBE_SOURCE}
