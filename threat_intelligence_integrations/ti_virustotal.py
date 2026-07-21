"""
ADDED FOR THREAT INTEL GUI: VirusTotal API client.
Supports hash, URL, domain lookup and file upload.
"""

import os
import base64
import logging
from typing import Dict, Any, Optional

import requests

# ADDED FOR THREAT INTEL GUI: Minimal logging, no secrets
logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"


def _get_api_key() -> Optional[str]:
    """ADDED FOR THREAT INTEL GUI: Read API key from env."""
    API_KEY = ""
    #return os.environ.get("VIRUSTOTAL_API_KEY", "").strip() or None
    return API_KEY

def _headers() -> Dict[str, str]:
    """ADDED FOR THREAT INTEL GUI: Request headers."""
    key = _get_api_key()
    if not key:
        return {}
    return {"x-apikey": key}


def analyze_hash(hash_value: str) -> Dict[str, Any]:
    """
    ADDED FOR THREAT INTEL GUI: Lookup file by hash (MD5/SHA1/SHA256).
    Returns dict with stats, engines, or error.
    """
    if not _get_api_key():
        return {"error": "VIRUSTOTAL_API_KEY not set"}
    hash_value = hash_value.strip()
    try:
        r = requests.get(
            f"{VT_BASE}/files/{hash_value}",
            headers=_headers(),
            timeout=30,
        )
        if r.status_code == 404:
            return {"error": "Hash not found in VirusTotal"}
        if r.status_code == 429:
            return {"error": "Rate limit exceeded. Try again later."}
        r.raise_for_status()
        data = r.json()
        return _parse_file_response(data)
    except requests.RequestException as e:
        logger.exception("VirusTotal hash request failed")
        return {"error": str(e) if "api" not in str(e).lower() else "Request failed"}


def analyze_url(url: str) -> Dict[str, Any]:
    """
    ADDED FOR THREAT INTEL GUI: Lookup URL. VirusTotal requires base64 URL as id.
    """
    if not _get_api_key():
        return {"error": "VIRUSTOTAL_API_KEY not set"}
    url = url.strip()
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = requests.get(
            f"{VT_BASE}/urls/{url_id}",
            headers=_headers(),
            timeout=30,
        )
        if r.status_code == 404:
            return {"error": "URL not found in VirusTotal"}
        if r.status_code == 429:
            return {"error": "Rate limit exceeded. Try again later."}
        r.raise_for_status()
        data = r.json()
        return _parse_url_response(data)
    except requests.RequestException as e:
        logger.exception("VirusTotal URL request failed")
        return {"error": str(e) if "api" not in str(e).lower() else "Request failed"}


def analyze_domain(domain: str) -> Dict[str, Any]:
    """ADDED FOR THREAT INTEL GUI: Lookup domain."""
    if not _get_api_key():
        return {"error": "VIRUSTOTAL_API_KEY not set"}
    domain = domain.strip().lower()
    try:
        r = requests.get(
            f"{VT_BASE}/domains/{domain}",
            headers=_headers(),
            timeout=30,
        )
        if r.status_code == 404:
            return {"error": "Domain not found in VirusTotal"}
        if r.status_code == 429:
            return {"error": "Rate limit exceeded. Try again later."}
        r.raise_for_status()
        data = r.json()
        return _parse_domain_response(data)
    except requests.RequestException as e:
        logger.exception("VirusTotal domain request failed")
        return {"error": str(e) if "api" not in str(e).lower() else "Request failed"}


def analyze_file(file_path: str) -> Dict[str, Any]:
    """
    ADDED FOR THREAT INTEL GUI: Upload file for analysis.
    VirusTotal file size limit: 32 MB for API v3.
    """
    if not _get_api_key():
        return {"error": "VIRUSTOTAL_API_KEY not set"}
    if not file_path or not os.path.isfile(file_path):
        return {"error": "File not found"}
    size = os.path.getsize(file_path)
    if size > 32 * 1024 * 1024:
        return {"error": "File too large (max 32 MB)"}
    try:
        with open(file_path, "rb") as f:
            r = requests.post(
                f"{VT_BASE}/files",
                headers=_headers(),
                files={"file": (os.path.basename(file_path), f)},
                timeout=120,
            )
        if r.status_code == 429:
            return {"error": "Rate limit exceeded. Try again later."}
        r.raise_for_status()
        data = r.json()
        analysis_id = data.get("data", {}).get("id")
        if analysis_id:
            return analyze_hash(analysis_id)
        return _parse_file_response(data)
    except requests.RequestException as e:
        logger.exception("VirusTotal file upload failed")
        return {"error": str(e) if "api" not in str(e).lower() else "Upload failed"}


def _parse_file_response(data: Dict) -> Dict[str, Any]:
    """ADDED FOR THREAT INTEL GUI: Extract stats from file response."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    engines = attrs.get("last_analysis_results", {})
    malicious = sum(1 for e in engines.values() if isinstance(e, dict) and e.get("category") == "malicious")
    suspicious = sum(1 for e in engines.values() if isinstance(e, dict) and e.get("category") == "suspicious")
    harmless = sum(1 for e in engines.values() if isinstance(e, dict) and e.get("category") == "harmless")
    top_detections = [
        {"engine": k, "result": v.get("result", "N/A") if isinstance(v, dict) else str(v)}
        for k, v in list(engines.items())[:10]
        if isinstance(v, dict) and v.get("category") in ("malicious", "suspicious")
    ]
    return {
        "type": "file",
        "malicious": stats.get("malicious", malicious),
        "suspicious": stats.get("suspicious", suspicious),
        "harmless": stats.get("harmless", harmless),
        "undetected": stats.get("undetected", 0),
        "top_detections": top_detections[:5],
        "sha256": attrs.get("sha256"),
        "md5": attrs.get("md5"),
    }


def _parse_url_response(data: Dict) -> Dict[str, Any]:
    """ADDED FOR THREAT INTEL GUI: Extract stats from URL response."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    engines = attrs.get("last_analysis_results", {})
    top_detections = [
        {"engine": k, "result": v.get("result", "N/A") if isinstance(v, dict) else str(v)}
        for k, v in list(engines.items())[:10]
        if isinstance(v, dict) and v.get("category") in ("malicious", "suspicious")
    ]
    return {
        "type": "url",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "top_detections": top_detections[:5],
    }


def _parse_domain_response(data: Dict) -> Dict[str, Any]:
    """ADDED FOR THREAT INTEL GUI: Extract stats from domain response."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    engines = attrs.get("last_analysis_results", {})
    top_detections = [
        {"engine": k, "result": v.get("result", "N/A") if isinstance(v, dict) else str(v)}
        for k, v in list(engines.items())[:10]
        if isinstance(v, dict) and v.get("category") in ("malicious", "suspicious")
    ]
    return {
        "type": "domain",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "top_detections": top_detections[:5],
    }
