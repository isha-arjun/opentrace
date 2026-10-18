from __future__ import annotations

import pytest

from backend.app.validation import normalize_public_target


@pytest.mark.parametrize(
    "value",
    [
        "http://localhost:3000",
        "http://127.0.0.1",
        "https://[::1]",
        "ftp://example.com",
        "example.com",
        "javascript:alert(1)",
        "https://user:pass@example.com",
        "https://192.168.1.20",
    ],
)
def test_reject_invalid_public_targets(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_public_target(value)


def test_accept_valid_public_https_target() -> None:
    result = normalize_public_target("https://example.com/path?x=1")
    assert result.scheme == "https"
    assert result.host == "example.com"
    assert result.normalized_url.startswith("https://example.com/")


def test_accept_valid_http_target_with_normalization() -> None:
    result = normalize_public_target("http://example.com")
    assert result.normalized_url == "http://example.com/"
