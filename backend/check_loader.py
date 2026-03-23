"""Load Prowler-derived check catalogs and format for LLM prompt inclusion.

Check catalogs live in backend/checks/{service}_checks.json — static files
extracted from Prowler (no runtime dependency). This module loads them,
compacts them to save tokens, and formats a text block for the user prompt.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CHECKS_DIR = Path(__file__).resolve().parent / "checks"


def load_service_checks(service: str) -> list[dict[str, Any]]:
    """Load the full check catalog for a service. Returns [] if file missing."""
    path = CHECKS_DIR / f"{service}_checks.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("checks", [])


def compact_checks(
    checks: list[dict[str, Any]],
    *,
    detailed: bool = False,
) -> list[dict[str, Any]]:
    """Create a token-efficient version of checks for prompt inclusion.

    detailed=True  → primary service: includes MITRE tags
    detailed=False → dependency services: id/title/severity/category only
    """
    compacted: list[dict[str, Any]] = []
    for check in checks:
        entry: dict[str, Any] = {
            "id": check["id"],
            "title": check["title"],
            "severity": check["severity"],
            "category": check["category"],
        }
        if detailed:
            mitre = check.get("mitre_attack", [])
            if mitre:
                entry["mitre"] = mitre
        compacted.append(entry)
    return compacted


def build_check_reference(
    primary_service: str,
    dependency_services: list[str] | None = None,
) -> dict[str, Any]:
    """Build the full check reference structure for a scan.

    Loads checks for the primary service (detailed) and each dependency
    service (compact). Returns a dict ready for format_check_reference().
    """
    primary_checks = load_service_checks(primary_service)

    result: dict[str, Any] = {
        "primary_service": primary_service,
        "primary_checks": compact_checks(primary_checks, detailed=True),
        "primary_check_count": len(primary_checks),
    }

    if dependency_services:
        dep_checks: dict[str, list[dict[str, Any]]] = {}
        for dep_svc in dependency_services:
            checks = load_service_checks(dep_svc)
            if checks:
                dep_checks[dep_svc] = compact_checks(checks, detailed=False)
        if dep_checks:
            result["dependency_checks"] = dep_checks

    return result


def format_check_reference(ref: dict[str, Any]) -> str:
    """Format the check reference as a text block for inclusion in the LLM prompt.

    Returns empty string if no checks are available (graceful fallback).
    """
    primary = ref.get("primary_checks", [])
    dep_checks: dict[str, list[dict[str, Any]]] = ref.get("dependency_checks", {})

    if not primary and not dep_checks:
        return ""

    lines: list[str] = [
        "Known security check patterns to guide your analysis. "
        "Match scan evidence against these patterns for comprehensive detection. "
        "When a finding aligns with a known check, use its severity as a baseline. "
        "You may also identify issues beyond this catalog.",
    ]

    if primary:
        svc = ref["primary_service"].upper()
        count = ref["primary_check_count"]
        lines.append(f"\nPrimary service checks ({count} patterns for {svc}):")
        lines.append(json.dumps(primary, separators=(",", ":")))

    if dep_checks:
        dep_summary = ", ".join(
            f"{svc}: {len(checks)}" for svc, checks in dep_checks.items()
        )
        lines.append(f"\nDependency service checks ({dep_summary}):")
        for svc, checks in dep_checks.items():
            lines.append(f"{svc.upper()}:")
            lines.append(json.dumps(checks, separators=(",", ":")))

    return "\n".join(lines)
