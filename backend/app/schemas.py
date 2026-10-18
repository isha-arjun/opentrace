from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class ScanTarget(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Target URL is required.")
        return value.strip()


class EvidenceItem(BaseModel):
    source: str
    check_id: str
    observed_value: str | None = None
    observed_at: str | None = None


class Finding(BaseModel):
    id: str
    title: str
    category: str
    severity: str
    status: str
    confidence: str
    explanation: str
    remediation: str
    documentation: str
    observed_value: str | None = None
    evidence: list[EvidenceItem] = []


class ScanSummary(BaseModel):
    total: int
    passed: int
    failed: int
    informational: int
    unavailable: int
    unknown: int


class ScanReport(BaseModel):
    target: str
    hostname: str
    scan_timestamp: str
    data_source: str
    summary: ScanSummary
    findings: list[Finding]
    scope: str
    limitations: str


class ScanResponse(BaseModel):
    ok: bool
    report: ScanReport | None = None
    error: str | None = None
