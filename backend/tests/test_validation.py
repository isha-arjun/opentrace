from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import DEFAULT_MDN_SCAN_URL
from backend.app.schemas import ScanRequest, ScanResponse
from backend.app.validation import normalize_public_target
from backend.app.observatory import run_scan


app = FastAPI(title="OpenTrace", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan", response_model=ScanResponse)
async def scan_target(payload: ScanRequest) -> ScanResponse:
    try:
        validate = normalize_public_target(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        report = await run_scan(validate.normalized_url)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return ScanResponse(ok=True, report=report)
