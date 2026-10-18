from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ValidationResult:
    normalized_url: str
    host: str
    scheme: str
    port: int | None = None


DEFAULT_MDN_SCAN_URL = "https://observatory-api.mdn.mozilla.net/api/v2/scan"

SUPPORTED_HTTP_SCHEMES = {"http", "https"}
