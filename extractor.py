"""ZIP extraction helpers with optional 7-Zip support."""

from __future__ import annotations

import locale
import os
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from config import DEFAULT_TEMP_ROOT


LogFunc = Callable[[str], None]


@dataclass
class ScanRoot:
    root: Path
    label: str


@dataclass
class PreparedSource:
    source_path: Path
    source_package: str
    work_dir: Path
    scan_roots: list[ScanRoot]
    extracted_zip_count: int


def prepare_source(source_path: Path, log: LogFunc) -> PreparedSource:
    """Prepare a ZIP or folder for scanning and recursively expand nested ZIP files."""

    source_path = source_path.resolve()
    work_dir = _create_work_dir(log)
    source_package = source_path.name
    scan_roots: list[ScanRoot] = []

    if source_path.is_file() and source_path.suffix.lower() == ".zip":
        payload_root = work_dir / "payload"
        payload_root.mkdir(parents=True, exist_ok=True)
        log(f"Extracting top-level ZIP: {source_path}")
        extract_zip(source_path, payload_root, log)
        scan_roots.append(ScanRoot(payload_root, ""))
    elif source_path.is_dir():
        log(f"Using selected folder as scan root: {source_path}")
        scan_roots.append(ScanRoot(source_path, ""))
    else:
        raise ValueError("Please select a ZIP file or a folder.")

    nested_root = work_dir / "__nested_archives__"
    extracted_count = extract_nested_zips(scan_roots, nested_root, log)
    if extracted_count:
        scan_roots.append(ScanRoot(nested_root, "__nested_archives__"))

    return PreparedSource(
        source_path=source_path,
        source_package=source_package,
        work_dir=work_dir,
        scan_roots=scan_roots,
        extracted_zip_count=extracted_count,
    )


def extract_nested_zips(scan_roots: list[ScanRoot], destination_root: Path, log: LogFunc) -> int:
    """Find and extract ZIP files inside the prepared source, including ZIPs inside ZIPs."""

    queue: list[Path] = []
    seen: set[str] = set()
    extracted_count = 0

    for scan_root in scan_roots:
        queue.extend(_find_zip_files(scan_root.root))

    while queue:
        zip_path = queue.pop(0)
        resolved_key = str(zip_path.resolve()).lower()
        if resolved_key in seen:
            continue
        seen.add(resolved_key)

        output_dir = destination_root / f"{extracted_count + 1:04d}_{_safe_name(zip_path.stem)}"
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            log(f"Extracting nested ZIP: {zip_path} -> {output_dir}")
            extract_zip(zip_path, output_dir, log)
            extracted_count += 1
            queue.extend(_find_zip_files(output_dir))
        except Exception as exc:
            log(f"Nested ZIP extraction failed for {zip_path}: {exc}")

    return extracted_count


def extract_zip(zip_path: Path, output_dir: Path, log: LogFunc) -> None:
    """Extract ZIP using 7-Zip when available, otherwise Python zipfile."""

    seven_zip = find_7zip()
    if seven_zip:
        try:
            _extract_with_7zip(seven_zip, zip_path, output_dir, log)
            return
        except Exception as exc:
            log(f"7-Zip extraction failed, falling back to zipfile: {exc}")

    _extract_with_zipfile(zip_path, output_dir, log)


def find_7zip() -> Path | None:
    """Locate 7z.exe from PATH or common installation paths."""

    found = shutil.which("7z.exe") or shutil.which("7z")
    if found:
        return Path(found)

    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "7-Zip" / "7z.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "7-Zip" / "7z.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _extract_with_7zip(seven_zip: Path, zip_path: Path, output_dir: Path, log: LogFunc) -> None:
    startupinfo = None
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    completed = subprocess.run(
        [
            str(seven_zip),
            "x",
            "-y",
            f"-o{output_dir}",
            str(zip_path),
        ],
        capture_output=True,
        text=True,
        encoding=locale.getpreferredencoding(False),
        errors="replace",
        timeout=900,
        startupinfo=startupinfo,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "7-Zip failed")
    log(f"7-Zip extracted {zip_path.name}")


def _extract_with_zipfile(zip_path: Path, output_dir: Path, log: LogFunc) -> None:
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            target_path = _safe_zip_target(output_dir, member.filename)
            if target_path is None:
                log(f"Skipped unsafe ZIP member: {member.filename}")
                continue

            if member.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
                continue

            target_path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member, "r") as source, target_path.open("wb") as target:
                shutil.copyfileobj(source, target)
    log(f"zipfile extracted {zip_path.name}")


def _safe_zip_target(output_dir: Path, member_name: str) -> Path | None:
    normalized = member_name.replace("\\", "/")
    member_path = Path(normalized)
    if member_path.is_absolute() or ".." in member_path.parts:
        return None

    target = output_dir / member_path
    try:
        target.resolve().relative_to(output_dir.resolve())
    except ValueError:
        return None
    return target


def _find_zip_files(root: Path) -> list[Path]:
    zip_files: list[Path] = []
    for current_root, _, files in os.walk(root):
        for file_name in files:
            if file_name.lower().endswith(".zip"):
                zip_files.append(Path(current_root) / file_name)
    return zip_files


def _create_work_dir(log: LogFunc) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    root = DEFAULT_TEMP_ROOT
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        root = Path(tempfile.gettempdir()) / "HSA_TMP"
        root.mkdir(parents=True, exist_ok=True)
        log(f"Falling back to temp directory: {root}")

    work_dir = root / f"HSA_{timestamp}"
    counter = 1
    while work_dir.exists():
        counter += 1
        work_dir = root / f"HSA_{timestamp}_{counter}"
    work_dir.mkdir(parents=True, exist_ok=True)
    log(f"Working directory: {work_dir}")
    return work_dir


def _safe_name(value: str) -> str:
    safe = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in value)
    return safe[:80] or "archive"
