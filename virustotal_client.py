"""VirusTotal API v3 client.

This client only queries existing file reports by SHA256. It never uploads files.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import requests


class VirusTotalClient:
    """Small wrapper around VirusTotal API v3 file lookup."""

    BASE_URL = "https://www.virustotal.com/api/v3/files"

    def __init__(self, api_key: str | None, delay_seconds: int = 15, timeout_seconds: int = 30):
        self.api_key = (api_key or "").strip()
        self.delay_seconds = max(0, int(delay_seconds))
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def lookup_file(self, sha256: str) -> dict[str, Any]:
        """Return normalized VirusTotal data for a SHA256 hash."""

        if not self.enabled:
            return self._skipped(sha256)

        url = f"{self.BASE_URL}/{sha256}"
        try:
            response = self.session.get(
                url,
                headers={"x-apikey": self.api_key},
                timeout=self.timeout_seconds,
            )
            if self.delay_seconds:
                time.sleep(self.delay_seconds)

            if response.status_code == 404:
                return self._not_found(sha256)
            if response.status_code == 429:
                return self._error(sha256, "Rate Limited", url)
            if not response.ok:
                return self._error(sha256, f"HTTP {response.status_code}", url)

            payload = response.json()
            attributes = payload.get("data", {}).get("attributes", {})
            return self._parse_attributes(sha256, attributes)
        except requests.RequestException as exc:
            return self._error(sha256, f"Request error: {exc}", url)
        except ValueError as exc:
            return self._error(sha256, f"Invalid JSON: {exc}", url)

    def _parse_attributes(self, sha256: str, attributes: dict[str, Any]) -> dict[str, Any]:
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        timeout = int(stats.get("timeout") or 0)
        total = malicious + suspicious + harmless + undetected + timeout

        analysis_results = attributes.get("last_analysis_results") or {}
        detected_vendors = []
        for vendor, result in analysis_results.items():
            category = result.get("category")
            verdict = result.get("result")
            if category in {"malicious", "suspicious"}:
                detected_vendors.append(f"{vendor}: {verdict or category}")

        threat_labels = _extract_threat_labels(attributes)
        total_votes = attributes.get("total_votes") or {}
        vote_harmless = int(total_votes.get("harmless") or 0)
        vote_malicious = int(total_votes.get("malicious") or 0)
        community_score = vote_harmless - vote_malicious

        return {
            "status": "Found",
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
            "vt_detection": f"{malicious}/{total}" if total else "0/0",
            "detected_vendors": "; ".join(detected_vendors),
            "threat_labels": "; ".join(threat_labels),
            "last_analysis_date": _format_unix_time(attributes.get("last_analysis_date")),
            "reputation": attributes.get("reputation", ""),
            "community_score": (
                f"{community_score} (harmless:{vote_harmless}, malicious:{vote_malicious})"
            ),
            "link": f"https://www.virustotal.com/gui/file/{sha256}",
        }

    def _skipped(self, sha256: str) -> dict[str, Any]:
        return {
            "status": "Skipped - no API key",
            "malicious": None,
            "suspicious": None,
            "harmless": None,
            "undetected": None,
            "timeout": None,
            "vt_detection": "Not Queried",
            "detected_vendors": "",
            "threat_labels": "",
            "last_analysis_date": "",
            "reputation": "",
            "community_score": "",
            "link": f"https://www.virustotal.com/gui/file/{sha256}",
        }

    def _not_found(self, sha256: str) -> dict[str, Any]:
        return {
            "status": "Not Found",
            "malicious": None,
            "suspicious": None,
            "harmless": None,
            "undetected": None,
            "timeout": None,
            "vt_detection": "Not Found",
            "detected_vendors": "",
            "threat_labels": "",
            "last_analysis_date": "",
            "reputation": "",
            "community_score": "",
            "link": f"https://www.virustotal.com/gui/file/{sha256}",
        }

    def _error(self, sha256: str, message: str, url: str) -> dict[str, Any]:
        return {
            "status": message,
            "malicious": None,
            "suspicious": None,
            "harmless": None,
            "undetected": None,
            "timeout": None,
            "vt_detection": "Error",
            "detected_vendors": "",
            "threat_labels": "",
            "last_analysis_date": "",
            "reputation": "",
            "community_score": "",
            "link": url.replace("/api/v3/files/", "/gui/file/"),
        }


def _extract_threat_labels(attributes: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    classification = attributes.get("popular_threat_classification") or {}

    suggested = classification.get("suggested_threat_label")
    if suggested:
        labels.append(str(suggested))

    for item in classification.get("popular_threat_name") or []:
        value = item.get("value") if isinstance(item, dict) else item
        if value:
            labels.append(str(value))

    for item in classification.get("popular_threat_category") or []:
        value = item.get("value") if isinstance(item, dict) else item
        if value:
            labels.append(str(value))

    return list(dict.fromkeys(labels))


def _format_unix_time(value: Any) -> str:
    if not value:
        return ""
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OSError):
        return str(value)

