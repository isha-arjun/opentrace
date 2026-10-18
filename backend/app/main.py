from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import httpx

from backend.app.config import DEFAULT_MDN_SCAN_URL
from backend.app.schemas import EvidenceItem, Finding, ScanReport, ScanSummary
from backend.app.validation import normalize_public_target


SEVERITY_MAP = {
    "pass": "low",
    "fail": "high",
    "warning": "medium",
    "info": "info",
    "unknown": "unknown",
}

HEADER_GUIDANCE = {
    "content-security-policy": {
        "title": "Content-Security-Policy",
        "category": "Headers",
        "explanation": "The browser is being asked to follow CSP restrictions that reduce the chance of script injection and data exfiltration.",
        "remediation": "Use a restrictive CSP that aligns with the site's actual script, style, and asset needs and review sources regularly.",
        "documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    },
    "strict-transport-security": {
        "title": "Strict-Transport-Security",
        "category": "Headers",
        "explanation": "HSTS tells browsers to enforce HTTPS for the host, reducing downgrade and cookie hijacking risks.",
        "remediation": "Serve HTTPS consistently and set a reasonable max-age with includeSubDomains when appropriate.",
        "documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    "referrer-policy": {
        "title": "Referrer-Policy",
        "category": "Headers",
        "explanation": "Referrer policy controls how much URL information is shared when users navigate from the site.",
        "remediation": "Use a strict or no-referrer policy that matches the site's privacy posture and navigation needs.",
        "documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "x-content-type-options": {
        "title": "X-Content-Type-Options",
        "category": "Headers",
        "explanation": "This header helps prevent browsers from interpreting resources as a different MIME type than intended.",
        "remediation": "Set the header to nosniff for served resources where content type confusion is a risk.",
        "documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "x-frame-options": {
        "title": "Framing protection",
        "category": "Headers",
        "explanation": "Framing protections help prevent clickjacking by limiting whether a page may be embedded in other sites.",
        "remediation": "Use a frame-ancestors policy or X-Frame-Options where appropriate, with a policy that matches legitimate embedding needs.",
        "documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    "cookies": {
        "title": "Cookie visibility",
        "category": "Privacy",
        "explanation": "This observation is only meaningful when the upstream service explicitly reports cookie information.",
        "remediation": "Review cookie flags, domains, and use cases with a privacy-first approach and document the site's data handling practices.",
        "documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
    },
}


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_status(value: Any) -> str:
    if value is None:
        return "unknown"
    status = str(value).strip().lower()
    if status in {"pass", "passed", "true", "ok"}:
        return "pass"
    if status in {"warn", "warning", "warning-only"}:
        return "warning"
    if status in {"fail", "failed", "false", "error"}:
        return "fail"
    if status in {"info", "informational"}:
        return "info"
    return status or "unknown"


def _result_value(result: dict[str, Any]) -> str | None:
    for key in ("observed", "value", "result", "score_description", "status", "data"):
        if key in result and result[key] not in (None, ""):
            value = result[key]
            if isinstance(value, (dict, list)):
                return json.dumps(value, ensure_ascii=True, sort_keys=True)[:2000]
            return str(value)
    return None


def _build_finding(test_name: str, test_result: dict[str, Any]) -> Finding:
    guidance = HEADER_GUIDANCE.get(test_name, {
        "title": test_name.replace("-", " ").title(),
        "category": "Observability",
        "explanation": "The site produced an observable result from the upstream scan. This does not prove compliance or overall security.",
        "remediation": "Review the attached evidence and align the configuration with the site's risk profile and supported use cases.",
        "documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    })

    status = _normalize_status(test_result.get("status") or test_result.get("result") or test_result.get("pass"))
    score = _safe_int(test_result.get("score"), 0)
    severity = SEVERITY_MAP.get(status, "unknown")
    if status == "pass" and score < 50:
        severity = "info"
    elif status == "fail" and score > 50:
        severity = "medium"
    elif status == "warning":
        severity = "medium"

    observed = _result_value(test_result)
    title = guidance["title"]
    evidence = [
        EvidenceItem(
            source="Mozilla HTTP Observatory",
            check_id=test_name,
            observed_value=observed,
            observed_at=datetime.now(timezone.utc).isoformat(),
        )
    ]

    confidence = "confirmed" if status in {"pass", "fail", "warning"} else "unknown"
    if test_name not in HEADER_GUIDANCE:
        confidence = "informational"

    return Finding(
        id=f"finding-{test_name}",
        title=title,
        category=guidance["category"],
        severity=severity,
        status=status,
        confidence=confidence,
        explanation=guidance["explanation"],
        remediation=guidance["remediation"],
        documentation=guidance["documentation"],
        observed_value=observed,
        evidence=evidence,
    )


def build_scan_report(target: str, payload: dict[str, Any]) -> ScanReport:
    tests = payload.get("tests") or payload.get("scan", {}).get("tests") or payload.get("results", {}).get("tests") or {}
    findings = [_build_finding(name, result) for name, result in tests.items() if isinstance(result, dict)]

    if not findings:
        findings = [
            Finding(
                id="finding-unknown",
                title="No supported checks were returned",
                category="Observability",
                severity="info",
                status="unknown",
                confidence="unknown",
                explanation="The upstream service returned no usable test block for this URL, which means the configuration cannot be interpreted with confidence.",
                remediation="Re-run the scan or inspect the upstream response. Do not infer security status from missing data.",
                documentation="https://developer.mozilla.org/en-US/docs/Web/HTTP",
                observed_value=json.dumps(payload, ensure_ascii=True, sort_keys=True)[:2000],
                evidence=[EvidenceItem(source="Mozilla HTTP Observatory", check_id="response", observed_value=json.dumps(payload, ensure_ascii=True, sort_keys=True)[:2000], observed_at=datetime.now(timezone.utc).isoformat())],
            )
        ]

    data_source = DEFAULT_MDN_SCAN_URL
    summary = ScanSummary(
        total=len(findings),
        passed=sum(1 for item in findings if item.status == "pass"),
        failed=sum(1 for item in findings if item.status == "fail"),
        informational=sum(1 for item in findings if item.status == "info"),
        unavailable=sum(1 for item in findings if item.status == "unknown" and item.severity == "info"),
        unknown=sum(1 for item in findings if item.status == "unknown"),
    )

    report = ScanReport(
        target=target,
        hostname=target.split("//", 1)[-1].split("/", 1)[0],
        scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        data_source=data_source,
        summary=summary,
        findings=findings,
        scope="Public security header and transparency observations from the Mozilla HTTP Observatory API. This is not a complete security audit.",
        limitations="Some headers may be absent or the upstream service may rate-limit or change schema. Missing data is an observation, not evidence of exploitability.",
    )
    return report


async def run_scan(target_url: str) -> ScanReport:
    validated = normalize_public_target(target_url)
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(
            DEFAULT_MDN_SCAN_URL,
            params={"host": validated.host},
            headers={"Accept": "application/json"},
        )

    if response.status_code == 429:
        raise RuntimeError("The upstream Observatory service is rate-limiting requests. Please try again in a moment.")
    if response.status_code >= 500:
        raise RuntimeError("The upstream Observatory service is temporarily unavailable.")
    if response.status_code >= 400:
        raise RuntimeError(f"The upstream service rejected the scan request: {response.status_code}.")

    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError("The upstream service returned invalid JSON.") from exc

    if not isinstance(payload, dict):
        raise RuntimeError("The upstream service returned an unexpected payload format.")

    return build_scan_report(validated.normalized_url, payload)
