"""Application-wide configuration for Homologation Security Analyzer."""

from __future__ import annotations

import os
from pathlib import Path


APP_NAME = "Homologation Security Analyzer"
APP_VERSION = "1.0.0"

# Keep extraction paths short to reduce Windows MAX_PATH issues.
DEFAULT_TEMP_ROOT = Path(os.environ.get("HSA_TEMP_ROOT", r"C:\HSA_TMP"))

# VirusTotal public API rate limit is commonly 4 requests/minute for free keys.
DEFAULT_VT_DELAY_SECONDS = int(os.environ.get("HSA_VT_DELAY_SECONDS", "15"))
VT_API_KEY_ENV = "VT_API_KEY"

TARGET_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".msi",
    ".cab",
    ".cat",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".jar",
    ".apk",
    ".zip",
    ".rar",
    ".7z",
}

HASH_REPORT_HEADERS = [
    "SourcePackage",
    "RelativePath",
    "FileName",
    "Extension",
    "SizeMB",
    "SHA256",
    "SHA1",
    "MD5",
    "SignatureStatus",
    "Publisher",
    "SignerSubject",
    "CertificateIssuer",
    "CompanyName",
    "ProductName",
    "FileVersion",
    "ProductVersion",
    "Description",
    "OriginalFilename",
    "VT_Status",
    "VT_Detection",
    "VT_Malicious",
    "VT_Suspicious",
    "VT_Harmless",
    "VT_Undetected",
    "VT_Timeout",
    "VT_DetectedVendors",
    "VT_ThreatLabels",
    "VT_LastAnalysisDate",
    "VT_Reputation",
    "VT_CommunityScore",
    "VT_Link",
    "RiskLevel",
    "Decision",
    "GLPI_Comment",
]

ALL_FILES_HEADERS = [
    "SourcePackage",
    "RelativePath",
    "FileName",
    "Extension",
    "SizeBytes",
    "SizeMB",
    "LastModified",
    "IsTargetFile",
]

