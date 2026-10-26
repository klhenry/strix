"""Evidence collection: screenshots and request/response artifacts."""

from __future__ import annotations

import base64
import logging
from io import BytesIO
from typing import TYPE_CHECKING

from PIL import Image, UnidentifiedImageError


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)


def normalize_screenshot(payload: bytes) -> bytes:
    """Decode bounded raster evidence and emit PNG, removing source metadata."""
    try:
        with Image.open(BytesIO(payload)) as image:
            if image.width * image.height > 20_000_000:
                raise ValueError("Screenshot exceeds 20 megapixels; crop or resize it first")
            image.load()
            output = BytesIO()
            # Flatten transparency onto white: simply dropping alpha can expose
            # RGB pixels hidden by a transparent redaction. Start with a fresh
            # image so EXIF, comments and other source metadata cannot follow.
            rgba = image.convert("RGBA")
            converted = Image.new("RGB", image.size, "white")
            converted.paste(rgba, mask=rgba.getchannel("A"))
            converted.save(output, format="PNG")
            if output.tell() > 10 * 1024 * 1024:
                raise ValueError("Normalized screenshot exceeds 10 MiB; crop or resize it first")
            return output.getvalue()
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError) as exc:
        raise ValueError("Screenshot must be a valid raster image") from exc


def collect_evidence(run_dir: Path) -> dict[str, list[Path]]:
    """Scan the evidence directory and return files grouped by identifier.

    Returns a dict mapping identifiers (e.g. "general" or vuln IDs) to lists
    of image file paths found in run_dir/evidence/.
    """
    evidence_dir = run_dir / "evidence"
    if not evidence_dir.exists():
        return {}

    result: dict[str, list[Path]] = {}
    image_extensions = {".png", ".jpg", ".jpeg", ".gif", ".webp"}

    for file_path in sorted(evidence_dir.iterdir()):
        if (
            file_path.suffix.lower() not in image_extensions
            or not file_path.is_file()
            or file_path.is_symlink()
        ):
            continue
        # Group by stem prefix: screenshot_browser_20260323_143000 -> "general"
        # or vuln-0001_screenshot_... -> "vuln-0001"
        stem = file_path.stem
        if stem.startswith("vuln-"):
            parts = stem.split("_", 1)
            key = parts[0]
        else:
            key = "general"

        result.setdefault(key, []).append(file_path)

    return result


def encode_evidence_base64(file_path: Path) -> str:
    """Read an image file and return its base64-encoded contents."""
    try:
        raw = file_path.read_bytes()
        return base64.b64encode(raw).decode("ascii")
    except OSError:
        logger.warning("Failed to read evidence file: %s", file_path)
        return ""


def save_screenshot(
    screenshot_b64: str,
    run_dir: Path,
    tool_name: str,
    timestamp: str,
) -> Path | None:
    """Persist a base64-encoded screenshot to the evidence directory.

    Returns the saved file path, or None on failure.
    """
    try:
        evidence_dir = run_dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)

        safe_tool = tool_name.replace("/", "_").replace(" ", "_")
        safe_ts = timestamp.replace(":", "").replace("-", "").replace(" ", "_")
        filename = f"screenshot_{safe_tool}_{safe_ts}.png"
        file_path = evidence_dir / filename

        file_path.write_bytes(base64.b64decode(screenshot_b64))
    except (OSError, ValueError):
        logger.debug("Failed to save screenshot evidence", exc_info=True)
        return None
    else:
        return file_path
