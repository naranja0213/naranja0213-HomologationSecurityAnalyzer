"""Hash helpers used by the scanner."""

from __future__ import annotations

import hashlib
from pathlib import Path


def calculate_hashes(file_path: Path, chunk_size: int = 1024 * 1024) -> dict[str, str]:
    """Calculate SHA256, SHA1, and MD5 for a file without loading it fully."""

    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    with file_path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return {
        "SHA256": sha256.hexdigest(),
        "SHA1": sha1.hexdigest(),
        "MD5": md5.hexdigest(),
    }

