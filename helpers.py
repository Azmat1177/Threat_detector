"""
helpers.py — External intelligence sources for ThreatDetector.

This module is intentionally narrow in scope: it knows how to talk to
external intelligence providers (VirusTotal, WHOIS) and how to normalize
their responses into small, JSON-serializable dictionaries. It contains no
Streamlit UI code, no Gemini/LLM code, and no orchestration logic.

Every public source function follows the same contract:

    get_source(target_type: str, target: str) -> dict

    Success -> {"source": "<Name>", "status": "success", "data": {...}}
    Failure -> {"source": "<Name>", "status": "error", "error": "..."}

To add a new intelligence source later:
    1. Write one `get_<source>(target_type, target)` function below that
       returns a dict following the contract above.
    2. Add one entry to the SOURCES registry at the bottom of this file.

No other file needs to change — app.py loops over SOURCES generically.
"""

from __future__ import annotations

import base64
import socket
from datetime import date, datetime
from urllib.parse import urlparse

import requests
import streamlit as st
import whois as pywhois

VT_BASE_URL = "https://www.virustotal.com/api/v3"
HTTP_TIMEOUT = 15  # seconds
WHOIS_TIMEOUT = 10  # seconds
IANA_WHOIS_SERVER = "whois.iana.org"
CACHE_TTL_SECONDS = 3600


def _get_secret(key: str) -> str | None:
    """Look up an API key: prefer what the user pasted into the running app this
    session, then fall back to an optional local secrets.toml. Never crashes if
    neither is present."""
    session_value = st.session_state.get(key)
    if session_value:
        return session_value
    try:
        return st.secrets.get(key)
    except Exception:
        return None


def _error(source: str, message: str) -> dict:
    return {"source": source, "status": "error", "error": message}


def _success(source: str, data: dict) -> dict:
    return {"source": source, "status": "success", "data": data}


# --------------------------------------------------------------------------
# VirusTotal
# --------------------------------------------------------------------------


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_virustotal(target_type: str, target: str) -> dict:
    """Query VirusTotal for reputation data on an IP, domain, or URL."""
    api_key = _get_secret("VIRUSTOTAL_API_KEY")
    if not api_key:
        return _error("VirusTotal", "VirusTotal API key not set — paste one in the API Keys section above.")

    if target_type == "IP Address":
        endpoint = f"{VT_BASE_URL}/ip_addresses/{target}"
    elif target_type == "Domain":
        endpoint = f"{VT_BASE_URL}/domains/{target}"
    elif target_type == "URL":
        url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
        endpoint = f"{VT_BASE_URL}/urls/{url_id}"
    else:
        return _error("VirusTotal", f"Unsupported target type: {target_type}")

    try:
        response = requests.get(
            endpoint, headers={"x-apikey": api_key}, timeout=HTTP_TIMEOUT
        )
    except requests.exceptions.RequestException as exc:
        return _error("VirusTotal", f"Network error contacting VirusTotal: {exc}")

    if response.status_code == 401:
        return _error("VirusTotal", "VirusTotal rejected the API key (unauthorized).")
    if response.status_code == 429:
        return _error("VirusTotal", "VirusTotal rate limit exceeded. Try again later.")
    if response.status_code == 404:
        return _success(
            "VirusTotal",
            {"found": False, "message": "No VirusTotal record found for this target yet."},
        )
    if response.status_code != 200:
        return _error("VirusTotal", f"VirusTotal returned HTTP {response.status_code}.")

    try:
        payload = response.json()
    except ValueError:
        return _error("VirusTotal", "VirusTotal returned an unparseable response.")

    attributes = payload.get("data", {}).get("attributes", {}) or {}
    stats = attributes.get("last_analysis_stats", {}) or {}

    summary_fields = (
        "reputation",
        "last_analysis_stats",
        "last_analysis_date",
        "categories",
        "country",
        "as_owner",
        "asn",
        "registrar",
        "creation_date",
        "total_votes",
        "tags",
        "times_submitted",
    )

    data = {
        "found": True,
        "reputation": attributes.get("reputation"),
        "malicious": stats.get("malicious"),
        "suspicious": stats.get("suspicious"),
        "undetected": stats.get("undetected"),
        "harmless": stats.get("harmless"),
        "total_engines": sum(stats.values()) if stats else None,
        "last_analysis_date": attributes.get("last_analysis_date"),
        "categories": attributes.get("categories"),
        "raw": {k: attributes[k] for k in summary_fields if k in attributes},
    }
    return _success("VirusTotal", data)


# --------------------------------------------------------------------------
# WHOIS
# --------------------------------------------------------------------------


def _normalize_date(value):
    """Collapse WHOIS date fields (which may be lists of datetimes) to a string."""
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _normalize_list(value):
    if value is None:
        return None
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _raw_whois_query(server: str, query: str) -> str:
    """Send a single raw WHOIS query to `server` on port 43 and return the text response."""
    with socket.create_connection((server, 43), timeout=WHOIS_TIMEOUT) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode(errors="replace")


def _extract_field(raw_text: str, field_names: list[str]) -> str | None:
    for line in raw_text.splitlines():
        for field in field_names:
            prefix = field.lower() + ":"
            if line.strip().lower().startswith(prefix):
                return line.split(":", 1)[1].strip()
    return None


def _ip_whois(ip: str) -> dict:
    """Resolve registration data for an IP address by following the IANA WHOIS referral."""
    referral_text = _raw_whois_query(IANA_WHOIS_SERVER, ip)
    server = _extract_field(referral_text, ["refer"]) or "whois.arin.org"
    raw_text = _raw_whois_query(server, ip)

    return {
        "whois_server": server,
        "organization": _extract_field(raw_text, ["OrgName", "org-name", "netname", "owner"]),
        "country": _extract_field(raw_text, ["Country", "country"]),
        "network_range": _extract_field(raw_text, ["NetRange", "inetnum", "CIDR"]),
        "raw": raw_text.strip(),
    }


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_whois(target_type: str, target: str) -> dict:
    """Look up WHOIS registration data for a domain, URL hostname, or IP address."""
    hostname = urlparse(target).hostname if target_type == "URL" else target
    hostname = hostname or target

    try:
        if target_type == "IP Address":
            ip_info = _ip_whois(hostname)
            data = {
                "found": bool(ip_info.get("raw")),
                "domain": hostname,
                "organization": ip_info.get("organization"),
                "country": ip_info.get("country"),
                "network_range": ip_info.get("network_range"),
                "whois_server": ip_info.get("whois_server"),
                "raw": ip_info.get("raw"),
            }
            return _success("WHOIS", data)

        record = pywhois.whois(hostname)
        record_dict = dict(record) if record else {}

        if not record_dict.get("domain_name"):
            return _success(
                "WHOIS",
                {"found": False, "domain": hostname, "message": "No WHOIS record found for this domain."},
            )

        data = {
            "found": True,
            "domain": hostname,
            "registrar": record_dict.get("registrar"),
            "creation_date": _normalize_date(record_dict.get("creation_date")),
            "expiration_date": _normalize_date(record_dict.get("expiration_date")),
            "updated_date": _normalize_date(record_dict.get("updated_date")),
            "name_servers": _normalize_list(record_dict.get("name_servers")),
            "status": _normalize_list(record_dict.get("status")),
            "raw": {k: str(v) for k, v in record_dict.items()},
        }
        return _success("WHOIS", data)
    except Exception as exc:
        return _error("WHOIS", f"WHOIS lookup failed: {exc}")


# --------------------------------------------------------------------------
# Source registry — the single point of extension for app.py
# --------------------------------------------------------------------------

SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
