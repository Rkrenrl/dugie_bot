"""Heuristic text and OCR detection for common Discord giveaway scams."""

from dataclasses import dataclass
from io import BytesIO
import re
from urllib.parse import urlparse


FLAG_THRESHOLD = 4

_MRBEAST = re.compile(r"\bmr\s*beast\b", re.IGNORECASE)
_FREE_NITRO = re.compile(
    r"\b(?:free\s+(?:discord\s+)?nitro|discord\s+nitro\s+(?:free|gift|giveaway)|nitro\s+gift)\b",
    re.IGNORECASE,
)
_GIVEAWAY = re.compile(
    r"\b(?:giveaway|give\s*away|winner|prize|claim\s+(?:your\s+)?(?:gift|reward|nitro))\b",
    re.IGNORECASE,
)
_ACTION = re.compile(
    r"\b(?:claim|click|visit|verify|connect|log\s*in|limited\s*time|hurry|expires?)\b",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s<>]+", re.IGNORECASE)
_SCAM_HOST_WORDS = re.compile(r"(?:nitro|discord|gift|claim|reward|beast)", re.IGNORECASE)
_OFFICIAL_HOSTS = {"discord.com", "discord.gg", "discord.gift"}


@dataclass(frozen=True)
class Detection:
    score: int
    reasons: tuple[str, ...]

    @property
    def is_scam(self) -> bool:
        return self.score >= FLAG_THRESHOLD


def detect_scam(text: str) -> Detection:
    """Score message or OCR text for common giveaway and Nitro scam signals."""
    score = 0
    reasons: list[str] = []

    if _MRBEAST.search(text):
        score += 3
        reasons.append("MrBeast giveaway branding")
    if _FREE_NITRO.search(text):
        score += 4
        reasons.append("free Discord Nitro offer")
    if _GIVEAWAY.search(text):
        score += 2
        reasons.append("giveaway or prize language")
    if _ACTION.search(text):
        score += 1
        reasons.append("claim, click, or verification prompt")

    for match in _URL.finditer(text):
        host = (urlparse(match.group(0).rstrip(".,!?;:)")).hostname or "").lower()
        if host not in _OFFICIAL_HOSTS and _SCAM_HOST_WORDS.search(host):
            score += 3
            reasons.append("link uses a suspicious giveaway-related domain")
            break

    return Detection(score=score, reasons=tuple(reasons))


def extract_image_text(image_bytes: bytes) -> str:
    """OCR an image attachment. Requires Pillow and the Tesseract executable."""
    from PIL import Image, ImageOps
    import pytesseract

    with Image.open(BytesIO(image_bytes)) as source:
        image = ImageOps.exif_transpose(source).convert("RGB")
        image.thumbnail((2200, 2200))
        return pytesseract.image_to_string(image, timeout=8)