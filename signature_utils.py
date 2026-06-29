"""Windows digital signature and version metadata helpers."""

from __future__ import annotations

import ctypes
import json
import locale
import os
import struct
import subprocess
from pathlib import Path


VERSION_FIELDS = [
    "ProductName",
    "CompanyName",
    "FileVersion",
    "ProductVersion",
    "FileDescription",
    "OriginalFilename",
]


def get_authenticode_signature(file_path: Path, timeout_seconds: int = 20) -> dict[str, str]:
    """Return Authenticode signature details by calling PowerShell on Windows."""

    if os.name != "nt":
        return {
            "SignatureStatus": "NotChecked",
            "Publisher": "",
            "SignerSubject": "",
            "CertificateIssuer": "",
        }

    literal_path = str(file_path).replace("'", "''")
    command = f"""
$ErrorActionPreference = 'SilentlyContinue'
$sig = Get-AuthenticodeSignature -LiteralPath '{literal_path}'
$cert = $sig.SignerCertificate
[pscustomobject]@{{
  SignatureStatus = if ($sig.Status) {{ $sig.Status.ToString() }} else {{ 'Unknown' }}
  Publisher = if ($cert) {{ $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }} else {{ '' }}
  SignerSubject = if ($cert) {{ $cert.Subject }} else {{ '' }}
  CertificateIssuer = if ($cert) {{ $cert.Issuer }} else {{ '' }}
}} | ConvertTo-Json -Compress
""".strip()

    try:
        startupinfo = None
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            encoding=locale.getpreferredencoding(False),
            errors="replace",
            timeout=timeout_seconds,
            startupinfo=startupinfo,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            error_message = completed.stderr.strip() or completed.stdout.strip() or "No signature output"
            return {
                "SignatureStatus": "Unknown",
                "Publisher": "",
                "SignerSubject": "",
                "CertificateIssuer": "",
                "SignatureError": error_message,
            }

        data = json.loads(completed.stdout.strip())
        status = data.get("SignatureStatus") or "Unknown"
        return {
            "SignatureStatus": status,
            "Publisher": data.get("Publisher") or "",
            "SignerSubject": data.get("SignerSubject") or "",
            "CertificateIssuer": data.get("CertificateIssuer") or "",
        }
    except Exception as exc:
        return {
            "SignatureStatus": "Unknown",
            "Publisher": "",
            "SignerSubject": "",
            "CertificateIssuer": "",
            "SignatureError": repr(exc),
        }


def get_file_version_info(file_path: Path) -> dict[str, str]:
    """Read common VERSIONINFO strings from PE files using Windows APIs."""

    result = {
        "ProductName": "",
        "CompanyName": "",
        "FileVersion": "",
        "ProductVersion": "",
        "Description": "",
        "OriginalFilename": "",
    }

    if os.name != "nt":
        return result

    try:
        version = ctypes.windll.version
        path = str(file_path)
        size = version.GetFileVersionInfoSizeW(path, None)
        if size == 0:
            return result

        buffer = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(path, 0, size, buffer):
            return result

        lang_codepage = _get_lang_codepage(version, buffer)
        for field in VERSION_FIELDS:
            value = _query_version_string(version, buffer, lang_codepage, field)
            if field == "FileDescription":
                result["Description"] = value
            else:
                result[field] = value
    except Exception as exc:
        result["VersionInfoError"] = repr(exc)
        return result

    return result


def _get_lang_codepage(version: ctypes.CDLL, buffer: ctypes.Array) -> str:
    pointer = ctypes.c_void_p()
    length = ctypes.c_uint()
    if version.VerQueryValueW(
        buffer, r"\VarFileInfo\Translation", ctypes.byref(pointer), ctypes.byref(length)
    ):
        raw = ctypes.string_at(pointer.value, length.value)
        if len(raw) >= 4:
            language, codepage = struct.unpack("<HH", raw[:4])
            return f"{language:04x}{codepage:04x}"
    return "040904b0"


def _query_version_string(
    version: ctypes.CDLL, buffer: ctypes.Array, lang_codepage: str, field: str
) -> str:
    pointer = ctypes.c_void_p()
    length = ctypes.c_uint()
    sub_block = rf"\StringFileInfo\{lang_codepage}\{field}"
    ok = version.VerQueryValueW(buffer, sub_block, ctypes.byref(pointer), ctypes.byref(length))
    if not ok or not pointer.value or length.value == 0:
        return ""
    return ctypes.wstring_at(pointer.value, length.value).rstrip("\x00")
