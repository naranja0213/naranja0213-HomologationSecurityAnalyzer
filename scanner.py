"""Main analysis pipeline."""

from __future__ import annotations

import json
import os
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from config import ALL_FILES_HEADERS, HASH_REPORT_HEADERS, TARGET_EXTENSIONS, VT_API_KEY_ENV
from excel_report import create_excel_report
from extractor import PreparedSource, ScanRoot, prepare_source
from hash_utils import calculate_hashes
from risk_engine import build_glpi_comment, evaluate_risk
from signature_utils import get_authenticode_signature, get_file_version_info
from virustotal_client import VirusTotalClient


ProgressCallback = Callable[[int, int, str], None]


@dataclass
class AnalysisResult:
    report_path: Path
    log_path: Path
    summary_path: Path
    json_path: Path
    total_files: int
    target_files: int


class AnalysisLogger:
    """Simple file logger so the GUI can run without configuring logging globals."""

    def __init__(self, log_path: Path, summary_path: Path):
        self.log_path = log_path
        self.summary_path = summary_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.log_path.open("a", encoding="utf-8")
        self._summary_handle = self.summary_path.open("w", encoding="utf-8", errors="replace")

    def info(self, message: str) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._handle.write(f"[{timestamp}] {message}\n")
        self._handle.flush()

    def summary(self, message: str) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._summary_handle.write(f"[{timestamp}] {message}\n")
        self._summary_handle.flush()

    def close(self) -> None:
        self._handle.close()
        self._summary_handle.close()


def analyze_source(
    source_path: str | Path,
    vt_api_key: str | None = None,
    vt_delay_seconds: int = 15,
    progress_callback: ProgressCallback | None = None,
) -> AnalysisResult:
    """Analyze a ZIP file or folder and create Excel, JSON, and log outputs."""

    source = Path(source_path).resolve()
    output_dir = source.parent
    safe_name = _safe_output_name(source.stem if source.is_file() else source.name)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_path = output_dir / f"Homologation_Report_{safe_name}_{timestamp}.xlsx"
    log_path = output_dir / f"analysis_log_{timestamp}.txt"
    summary_path = output_dir / "Summary.txt"
    json_path = output_dir / f"Homologation_Result_{timestamp}.json"

    logger = AnalysisLogger(log_path, summary_path)
    try:
        logger.info("Analysis started")
        logger.info(f"Source path: {source}")
        logger.summary(f"Analysis started for: {source}")
        _progress(progress_callback, 0, 100, "Preparing source")

        prepared = prepare_source(source, logger.info)
        all_files = _collect_files(prepared.scan_roots, prepared.source_package, logger.info)
        target_files = [item for item in all_files if item["path"].suffix.lower() in TARGET_EXTENSIONS]

        logger.info(f"Total files: {len(all_files)}")
        logger.info(f"Target files: {len(target_files)}")
        logger.info(f"Nested ZIPs extracted: {prepared.extracted_zip_count}")

        api_key = (vt_api_key or os.environ.get(VT_API_KEY_ENV) or "").strip()
        vt_client = VirusTotalClient(api_key, delay_seconds=vt_delay_seconds)
        if vt_client.enabled:
            logger.info("VirusTotal lookup enabled")
        else:
            logger.info("VirusTotal lookup skipped because no API key was provided")

        hash_rows: list[dict[str, Any]] = []
        total_targets = max(len(target_files), 1)

        for index, file_item in enumerate(target_files, start=1):
            file_path = file_item["path"]
            message = f"Analyzing {index}/{len(target_files)}: {file_path.name}"
            _progress(progress_callback, index, total_targets, message)
            logger.info(message)

            try:
                row = _analyze_file(file_item, prepared, vt_client, logger.info, logger.summary)
                hash_rows.append(row)
            except Exception as exc:
                logger.info(f"Failed to analyze {file_path}: {exc}")
                logger.summary(
                    "File analysis failed: "
                    f"{file_path}\nException: {exc!r}\n{traceback.format_exc()}"
                )

        all_file_rows = [_all_file_row(item) for item in all_files]
        summary = _build_summary(source, all_files, hash_rows)

        logger.info(f"Writing Excel report: {report_path}")
        create_excel_report(report_path, summary, hash_rows, all_file_rows)

        logger.info(f"Writing JSON result: {json_path}")
        _write_json(json_path, summary, hash_rows, all_file_rows)

        logger.info("Analysis completed")
        logger.summary("Analysis completed")
        _progress(progress_callback, total_targets, total_targets, f"Completed: {report_path}")

        return AnalysisResult(
            report_path=report_path,
            log_path=log_path,
            summary_path=summary_path,
            json_path=json_path,
            total_files=len(all_files),
            target_files=len(target_files),
        )
    finally:
        logger.close()


def _analyze_file(
    file_item: dict[str, Any],
    prepared: PreparedSource,
    vt_client: VirusTotalClient,
    log: Callable[[str], None],
    summary_log: Callable[[str], None],
) -> dict[str, Any]:
    file_path: Path = file_item["path"]
    stat = file_path.stat()

    hashes = calculate_hashes(file_path)
    signature = _safe_signature(file_path, summary_log)
    version_info = _safe_version_info(file_path, summary_log)
    vt = vt_client.lookup_file(hashes["SHA256"])

    risk = evaluate_risk(
        vt.get("malicious"),
        signature.get("SignatureStatus", ""),
        signature.get("Publisher", ""),
        signature.get("SignerSubject", ""),
        version_info.get("CompanyName", ""),
    )

    row = {
        "SourcePackage": prepared.source_package,
        "RelativePath": file_item["relative_path"],
        "FileName": file_path.name,
        "Extension": file_path.suffix.lower(),
        "SizeMB": round(stat.st_size / (1024 * 1024), 4),
        "SHA256": hashes["SHA256"],
        "SHA1": hashes["SHA1"],
        "MD5": hashes["MD5"],
        "SignatureStatus": signature.get("SignatureStatus", ""),
        "Publisher": signature.get("Publisher", ""),
        "SignerSubject": signature.get("SignerSubject", ""),
        "CertificateIssuer": signature.get("CertificateIssuer", ""),
        "CompanyName": version_info.get("CompanyName", ""),
        "ProductName": version_info.get("ProductName", ""),
        "FileVersion": version_info.get("FileVersion", ""),
        "ProductVersion": version_info.get("ProductVersion", ""),
        "Description": version_info.get("Description", ""),
        "OriginalFilename": version_info.get("OriginalFilename", ""),
        "VT_Status": vt.get("status", ""),
        "VT_Detection": vt.get("vt_detection", ""),
        "VT_Malicious": _blank_if_none(vt.get("malicious")),
        "VT_Suspicious": _blank_if_none(vt.get("suspicious")),
        "VT_Harmless": _blank_if_none(vt.get("harmless")),
        "VT_Undetected": _blank_if_none(vt.get("undetected")),
        "VT_Timeout": _blank_if_none(vt.get("timeout")),
        "VT_DetectedVendors": vt.get("detected_vendors", ""),
        "VT_ThreatLabels": vt.get("threat_labels", ""),
        "VT_LastAnalysisDate": vt.get("last_analysis_date", ""),
        "VT_Reputation": vt.get("reputation", ""),
        "VT_CommunityScore": vt.get("community_score", ""),
        "VT_Link": vt.get("link", ""),
        "RiskLevel": risk["RiskLevel"],
        "Decision": risk["Decision"],
    }
    row["GLPI_Comment"] = build_glpi_comment(row)

    if row["RiskLevel"] == "High":
        log(f"High risk decision for {file_path}: {row['Decision']}")

    return {header: row.get(header, "") for header in HASH_REPORT_HEADERS}


def _safe_signature(file_path: Path, summary_log: Callable[[str], None]) -> dict[str, str]:
    try:
        signature = get_authenticode_signature(file_path)
        error = signature.pop("SignatureError", "")
        if error:
            summary_log(f"Signature extraction failed: {file_path}\nException: {error}")
        return signature
    except Exception as exc:
        summary_log(
            "Signature extraction failed: "
            f"{file_path}\nException: {exc!r}\n{traceback.format_exc()}"
        )
        return {
            "SignatureStatus": "Unknown",
            "Publisher": "",
            "SignerSubject": "",
            "CertificateIssuer": "",
        }


def _safe_version_info(file_path: Path, summary_log: Callable[[str], None]) -> dict[str, str]:
    try:
        version_info = get_file_version_info(file_path)
        error = version_info.pop("VersionInfoError", "")
        if error:
            summary_log(f"Version info extraction failed: {file_path}\nException: {error}")
        return version_info
    except Exception as exc:
        summary_log(
            "Version info extraction failed: "
            f"{file_path}\nException: {exc!r}\n{traceback.format_exc()}"
        )
        return {
            "ProductName": "",
            "CompanyName": "",
            "FileVersion": "",
            "ProductVersion": "",
            "Description": "",
            "OriginalFilename": "",
        }


def _collect_files(
    scan_roots: list[ScanRoot],
    source_package: str,
    log: Callable[[str], None],
) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    seen: set[str] = set()

    for scan_root in scan_roots:
        for current_root, dir_names, file_names in os.walk(scan_root.root, followlinks=False):
            dir_names[:] = [name for name in dir_names if not _is_ignored_dir(name)]
            for file_name in file_names:
                path = Path(current_root) / file_name
                try:
                    key = str(path.resolve()).lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    relative_path = _relative_path(path, scan_root)
                    files.append(
                        {
                            "path": path,
                            "source_package": source_package,
                            "relative_path": relative_path,
                        }
                    )
                except OSError as exc:
                    log(f"Skipping inaccessible file {path}: {exc}")

    files.sort(key=lambda item: item["relative_path"].lower())
    return files


def _all_file_row(item: dict[str, Any]) -> dict[str, Any]:
    path: Path = item["path"]
    try:
        stat = path.stat()
        modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        size_bytes = stat.st_size
    except OSError:
        modified = ""
        size_bytes = 0

    row = {
        "SourcePackage": item["source_package"],
        "RelativePath": item["relative_path"],
        "FileName": path.name,
        "Extension": path.suffix.lower(),
        "SizeBytes": size_bytes,
        "SizeMB": round(size_bytes / (1024 * 1024), 4),
        "LastModified": modified,
        "IsTargetFile": "Yes" if path.suffix.lower() in TARGET_EXTENSIONS else "No",
    }
    return {header: row.get(header, "") for header in ALL_FILES_HEADERS}


def _build_summary(
    source: Path,
    all_files: list[dict[str, Any]],
    hash_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    signed_count = sum(1 for row in hash_rows if row.get("SignatureStatus") == "Valid")
    unsigned_count = sum(1 for row in hash_rows if row.get("SignatureStatus") == "NotSigned")
    vt_detected_count = sum(1 for row in hash_rows if _as_int(row.get("VT_Malicious")) > 0)
    approved_count = sum(1 for row in hash_rows if "Approved" in str(row.get("Decision", "")))
    manual_count = sum(
        1 for row in hash_rows if "manual review" in str(row.get("Decision", "")).lower()
    )
    high_count = sum(
        1
        for row in hash_rows
        if row.get("RiskLevel") == "High" or "Reject" in str(row.get("Decision", ""))
    )

    return {
        "Source path": str(source),
        "Total files": len(all_files),
        "Target files": len(hash_rows),
        "Signed files": signed_count,
        "Unsigned files": unsigned_count,
        "VT detected files": vt_detected_count,
        "Approved count": approved_count,
        "Manual review count": manual_count,
        "High risk count": high_count,
        "Generated time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _write_json(
    json_path: Path,
    summary: dict[str, Any],
    hash_rows: list[dict[str, Any]],
    all_file_rows: list[dict[str, Any]],
) -> None:
    payload = {
        "summary": summary,
        "hash_report": hash_rows,
        "all_files": all_file_rows,
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _relative_path(path: Path, scan_root: ScanRoot) -> str:
    relative = path.relative_to(scan_root.root)
    text = str(relative)
    if scan_root.label:
        return str(Path(scan_root.label) / relative)
    return text


def _progress(callback: ProgressCallback | None, current: int, total: int, message: str) -> None:
    if callback:
        callback(current, total, message)


def _safe_output_name(value: str) -> str:
    safe = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in value)
    return safe[:80] or "source"


def _blank_if_none(value: Any) -> Any:
    return "" if value is None else value


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _is_ignored_dir(name: str) -> bool:
    return name in {".git", "__pycache__", ".venv", "venv"}
