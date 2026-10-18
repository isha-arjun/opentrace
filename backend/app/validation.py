from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from backend.app.config import DEFAULT_MDN_SCAN_URL, SUPPORTED_HTTP_SCHEMES, ValidationResult


_HOSTNAME_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def _is_public_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    return True


def normalize_public_target(raw_value: str) -> ValidationResult:
    if raw_value is None:
        raise ValueError("A target URL is required.")

    value = raw_value.strip()
    if not value:
        raise ValueError("A target URL is required.")

    if value.startswith("//"):
        raise ValueError("Use an explicit HTTP or HTTPS scheme.")

    split = urlsplit(value)
    scheme = (split.scheme or "").lower()
    if scheme not in SUPPORTED_HTTP_SCHEMES:
        raise ValueError("Only HTTP and HTTPS URLs are supported for public scans.")

    if split.username or split.password:
        raise ValueError("Credentials in URLs are not allowed for public scans.")

    host = split.hostname
    if not host:
        raise ValueError("The URL does not include a hostname.")

    lower_host = host.lower()
    if lower_host == "localhost" or lower_host.endswith(".localhost"):
        raise ValueError("localhost targets are not allowed for public scans.")

    if ":" in host and not host.startswith("["):
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("Malformed host in URL.") from exc

    if lower_host.endswith(".local"):
        raise ValueError("Local network hostnames are not allowed for public scans.")

    if not re.match(r"^[A-Za-z0-9.-]+$", host):
        raise ValueError("Malformed hostname.")

    if _HOSTNAME_RE.match(host) is None:
        try:
            ipaddress.ip_address(host)
            if not _is_public_ip(host):
                raise ValueError("Private, reserved, or local IP addresses are not allowed.")
        except ValueError:
            raise ValueError("Malformed hostname.")

    if host.startswith(".") or host.endswith("."):
        raise ValueError("Malformed hostname.")

    try:
        ipaddress.ip_address(host)
        if not _is_public_ip(host):
            raise ValueError("Private, reserved, or local IP addresses are not allowed.")
    except ValueError:
        pass

    netloc = split.netloc
    if "@" in netloc:
        raise ValueError("Credentials are not allowed in public URLs.")

    normalized = value.rstrip()
    if not normalized.endswith("/") and not split.path:
        normalized = normalized + "/"

    if split.port is not None and split.port in {0, 1, 22, 3389}:
        raise ValueError("Unsupported port for public scans.")

    return ValidationResult(
        normalized_url=normalized,
        host=host,
        scheme=scheme,
        port=split.port,
    )
