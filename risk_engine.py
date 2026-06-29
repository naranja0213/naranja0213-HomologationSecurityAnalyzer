"""Risk and decision rules for homologation review."""

from __future__ import annotations

from typing import Any


def is_microsoft_known_source(*values: str) -> bool:
    text = " ".join(value or "" for value in values).lower()
    return "microsoft" in text


def evaluate_risk(
    malicious: int | None,
    signature_status: str,
    publisher: str = "",
    signer_subject: str = "",
    company_name: str = "",
) -> dict[str, str]:
    """Apply the requested decision rules."""

    status = (signature_status or "").strip()
    is_valid = status == "Valid"
    is_not_signed = status in {"NotSigned", "Unknown", ""}
    is_microsoft = is_microsoft_known_source(publisher, signer_subject, company_name)

    if malicious is None:
        if is_microsoft and is_valid:
            return {
                "RiskLevel": "Low",
                "Decision": "Approved after manual review",
            }
        return {
            "RiskLevel": "Unknown",
            "Decision": "Manual Review Required",
        }

    if is_microsoft and malicious <= 1:
        return {
            "RiskLevel": "Low",
            "Decision": "Approved after manual review",
        }

    if malicious == 0 and is_valid:
        return {"RiskLevel": "Low", "Decision": "Approved"}

    if malicious == 0 and is_not_signed:
        return {
            "RiskLevel": "Low",
            "Decision": "Approved after manual review",
        }

    if 1 <= malicious <= 2 and is_valid:
        return {
            "RiskLevel": "Low",
            "Decision": "Likely false positive / Approved after manual review",
        }

    if 1 <= malicious <= 2 and is_not_signed:
        return {
            "RiskLevel": "Medium",
            "Decision": "Manual Review Required",
        }

    if 3 <= malicious <= 5:
        return {
            "RiskLevel": "Medium",
            "Decision": "Medium Risk / Manual Review Required",
        }

    if malicious > 5:
        return {
            "RiskLevel": "High",
            "Decision": "High Risk / Reject or escalate",
        }

    return {
        "RiskLevel": "Unknown",
        "Decision": "Manual Review Required",
    }


def build_glpi_comment(record: dict[str, Any]) -> str:
    """Generate a concise English GLPI note from the scan result."""

    publisher = record.get("Publisher") or "the publisher"
    vt_detection = record.get("VT_Detection") or "Not Queried"
    sha256 = record.get("SHA256") or "the SHA256 hash"
    signature_status = record.get("SignatureStatus") or ""
    decision = record.get("Decision") or "manual review"

    if signature_status == "Valid":
        return (
            f"Software manually reviewed. Valid digital signature from {publisher}. "
            f"VirusTotal analysis reports {vt_detection} detections. "
            "Based on signature verification, trusted source and manual review, "
            f"the software is {decision.lower()} for installation."
        )

    if signature_status == "NotSigned":
        return (
            "Software manually reviewed. The executable is not digitally signed. "
            f"VirusTotal analysis reports {vt_detection} detections. "
            f"SHA256 hash has been recorded: {sha256}. "
            "Based on source verification and manual review, the software is approved "
            "after manual verification."
        )

    return (
        "Software manually reviewed. Digital signature status could not be fully verified. "
        f"VirusTotal analysis reports {vt_detection} detections. "
        f"SHA256 hash has been recorded: {sha256}. "
        f"Final decision: {decision}."
    )

