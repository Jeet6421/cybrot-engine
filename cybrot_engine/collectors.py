"""Passive collectors. Each function turns one public source's answer into findings with a source label."""
import datetime as dt
import re
import urllib.parse

from . import net

RDAP_URL = "https://rdap.org/domain/{domain}"
CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
RDAP_SOURCE = "RDAP via rdap.org"
DNS_SOURCE = "DNS over HTTPS (Cloudflare, Google fallback)"
CT_SOURCE = "Certificate Transparency logs via crt.sh"
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _clean_txt(value):
    """DNS resolvers return TXT strings in quotes, sometimes split into several quoted parts."""
    return str(value).replace('" "', "").strip().strip('"')


def _vcard_field(entity, field):
    card = entity.get("vcardArray")
    if not card or len(card) < 2:
        return None
    for row in card[1]:
        if isinstance(row, list) and len(row) >= 4 and row[0] == field and isinstance(row[3], str):
            return row[3]
    return None


def rdap(domain):
    data = net.fetch_json(RDAP_URL.format(domain=urllib.parse.quote(domain)))
    if data is None:
        return {"found": False, "note": "No registration record was returned by RDAP.", "source": RDAP_SOURCE}
    events = {event.get("eventAction"): event.get("eventDate") for event in data.get("events", [])}
    registrar = None
    for entity in data.get("entities", []):
        if "registrar" in (entity.get("roles") or []):
            registrar = _vcard_field(entity, "fn")
            break
    name_servers = sorted(
        {str(ns.get("ldhName", "")).lower() for ns in data.get("nameservers", []) if ns.get("ldhName")}
    )
    return {
        "found": True,
        "registrar": registrar,
        "created": events.get("registration"),
        "expires": events.get("expiration"),
        "last_updated": events.get("last changed"),
        "status": data.get("status", []),
        "name_servers": name_servers,
        "source": RDAP_SOURCE,
    }


def dns_records(domain):
    records = []
    for rtype in DNS_RECORD_TYPES:
        answer = net.doh_query(domain, rtype)
        for item in answer.get("Answer") or []:
            if net.DNS_TYPES.get(item.get("type")) != rtype:
                continue  # e.g. a CNAME chain returned for an A query; CNAME is queried on its own
            value = str(item.get("data", "")).strip()
            if rtype == "TXT":
                value = _clean_txt(value)
            records.append({"type": rtype, "value": value, "ttl": item.get("TTL"), "source": DNS_SOURCE})
    return records


def dns_notes(records):
    notes = []
    types = {record["type"] for record in records}
    if "A" not in types and "AAAA" not in types:
        notes.append("No A or AAAA record was returned for the domain.")
    if "MX" not in types:
        notes.append("No MX record was returned, so no mail server is published for this domain.")
    ns_count = sum(1 for record in records if record["type"] == "NS")
    if ns_count < 2:
        notes.append(f"{ns_count} name server record(s) returned; two or more is the usual practice for redundancy.")
    return notes


def email_security(domain, records):
    spf = None
    for record in records:
        if record["type"] == "TXT" and record["value"].lower().startswith("v=spf1"):
            spf = record["value"]
            break
    dmarc_answer = net.doh_query(f"_dmarc.{domain}", "TXT")
    dmarc = None
    for item in dmarc_answer.get("Answer") or []:
        value = _clean_txt(item.get("data", ""))
        if value.lower().startswith("v=dmarc1"):
            dmarc = value
            break
    policy = None
    if dmarc:
        match = re.search(r"\bp=(none|quarantine|reject)\b", dmarc, re.I)
        policy = match.group(1).lower() if match else None
    return {
        "spf": spf,
        "dmarc": dmarc,
        "dmarc_policy": policy,
        "dkim": "Not checked. DKIM needs a selector name, which this engine does not guess.",
        "source": DNS_SOURCE,
    }


def ct_entries(domain):
    data = net.fetch_json(CRT_URL.format(domain=urllib.parse.quote(domain)), timeout=60)
    if data is None:
        return []
    if not isinstance(data, list):
        raise net.NetError("crt.sh returned an unexpected answer.")
    return data


def _names_of(entry):
    return [line.strip().lower() for line in str(entry.get("name_value", "")).splitlines() if line.strip()]


def subdomains_from_ct(entries, domain):
    """Deduplicated subdomains seen in certificates. These are discovered names, not verified live hosts."""
    first_seen = {}
    wildcard_seen = False
    suffix = "." + domain
    for entry in entries:
        stamp = entry.get("entry_timestamp") or entry.get("not_before")
        for name in _names_of(entry):
            if name.startswith("*."):
                wildcard_seen = True
                name = name[2:]
            if not name.endswith(suffix) or " " in name:
                continue
            if name not in first_seen or (stamp and stamp < first_seen[name]):
                first_seen[name] = stamp
    details = [
        {"name": name, "first_seen": first_seen[name], "source": CT_SOURCE, "verified_live": False}
        for name in sorted(first_seen)
    ]
    return details, wildcard_seen


def certificates_from_ct(entries, domain):
    suffix = "." + domain
    seen = {}
    for entry in entries:
        names = _names_of(entry)
        if not any(name == domain or name.endswith(suffix) or name.endswith("." + domain) for name in names):
            continue
        key = entry.get("id") or entry.get("serial_number") or len(seen)
        seen[key] = {
            "crt_sh_id": entry.get("id"),
            "issuer": entry.get("issuer_name"),
            "not_before": _utc(entry.get("not_before")),
            "not_after": _utc(entry.get("not_after")),
            "names": sorted(set(names))[:20],
            "source": CT_SOURCE,
        }
    certs = sorted(seen.values(), key=lambda c: c["not_after"] or "", reverse=True)
    return certs[:10]


def _utc(text):
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(text).replace("Z", ""))
    except ValueError:
        return str(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.isoformat()
