from __future__ import annotations

from app.db.models import AssetService, Exposure, Host, NvdCVECache


def compute_risk_score(cve: NvdCVECache, host: Host, exposures: list[Exposure]) -> float:
    cvss = cve.cvss_v3_score if cve.cvss_v3_score is not None else 0.0
    kev_factor = 1.5 if cve.is_in_kev else 1.0
    epss_factor = _epss_factor(cve.epss_score)
    criticality_factor = {"high": 1.5, "medium": 1.0, "low": 0.5}.get(host.criticality, 1.0)
    exposure_factor = _max_exposure_factor(exposures)
    return round(cvss * kev_factor * epss_factor * criticality_factor * exposure_factor, 2)


def risk_level(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 12:
        return "high"
    if score >= 6:
        return "medium"
    return "low"


def match_confidence(service: AssetService, cpe: str) -> str:
    if service.cpe and service.cpe == cpe and service.version and f":{service.version}:" in cpe:
        return "high"
    if service.cpe_confidence == "low":
        return "low"
    return "medium"


def _epss_factor(epss: float | None) -> float:
    if epss is None:
        return 1.0
    if epss >= 0.8:
        return 1.5
    if epss >= 0.5:
        return 1.3
    if epss >= 0.2:
        return 1.1
    return 1.0


def _max_exposure_factor(exposures: list[Exposure]) -> float:
    if not exposures:
        return 0.8
    values = {
        "public": 1.5,
        "internal": 1.0,
        "isolated": 0.3,
        "unknown": 0.8,
    }
    return max(values.get(e.exposure_scope, 0.8) for e in exposures)

