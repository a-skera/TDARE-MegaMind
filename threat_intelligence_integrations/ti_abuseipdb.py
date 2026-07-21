"""
ADDED FOR THREAT INTEL GUI: AbuseIPDB API client for IP reputation.
"""

import os
import logging
from typing import Dict, Any, Optional

import requests

# ADDED FOR THREAT INTEL GUI: Minimal logging, no secrets
logger = logging.getLogger(__name__)

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


def _get_api_key() -> Optional[str]:
    """ADDED FOR THREAT INTEL GUI: Read API key from env."""
    API_KEY = ""
    #return os.environ.get("ABUSEIPDB_API_KEY", "").strip() or None
    return API_KEY

def _headers() -> Dict[str, str]:
    """ADDED FOR THREAT INTEL GUI: Request headers."""
    key = _get_api_key()
    if not key:
        return {}
    return {"Key": key, "Accept": "application/json"}


def check_ip(ip: str) -> Dict[str, Any]:
    """
    ADDED FOR THREAT INTEL GUI: Check IP reputation via AbuseIPDB.
    Returns dict with abuse confidence, reports, ISP, country, etc.
    """
    if not _get_api_key():
        return {"error": "ABUSEIPDB_API_KEY not set"}
    ip = ip.strip()
    try:
        r = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers=_headers(),
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=30,
        )
        if r.status_code == 429:
            return {"error": "Rate limit exceeded. Try again later."}
        if r.status_code == 422:
            return {"error": "Invalid IP address"}
        r.raise_for_status()
        data = r.json().get("data", {})
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "isp": data.get("isp", "N/A"),
            "country": data.get("countryName", "N/A"),
            "country_code": data.get("countryCode", "N/A"),
            "domain": data.get("domain", "N/A"),
            "last_reported_at": data.get("lastReportedAt", "N/A"),
            "usage_type": data.get("usageType", "N/A"),
        }
    except requests.RequestException as e:
        logger.exception("AbuseIPDB request failed")
        return {"error": str(e) if "api" not in str(e).lower() else "Request failed"}
