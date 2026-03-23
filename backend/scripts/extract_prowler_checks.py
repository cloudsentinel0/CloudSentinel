#!/usr/bin/env python3
"""Extract Prowler check metadata into CloudSentinel check catalogs.

Reads the cloned Prowler repository and produces per-service JSON files
in backend/checks/ that CloudSentinel can use as a static check knowledge base.

No runtime dependency on Prowler — this is a one-time extraction tool.

Usage:
    python extract_prowler_checks.py --prowler-root /path/to/prowler
    python extract_prowler_checks.py  # defaults to ~/Downloads/prowler
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
OUTPUT_DIR = BACKEND_DIR / "checks"

# ---------------------------------------------------------------------------
# Mappings
# ---------------------------------------------------------------------------

# Which Prowler service directories to scan, and what CloudSentinel service
# they map to.
PROWLER_TO_CS_SERVICE: dict[str, str] = {
    "ec2": "ec2",
    "s3": "s3",
    "iam": "iam",
    "vpc": "vpc",
    "rds": "rds",
    "elb": "elb",
    "elbv2": "elb",
}

# EC2 check-name prefixes that should be split to their own service catalog.
EC2_SUBSERVICE_PREFIXES: dict[str, str] = {
    "ec2_ebs_": "ebs",
    "ec2_ami_": "ami",
}

# Prowler's Categories[] → CloudSentinel category.
CATEGORY_MAP: dict[str, str] = {
    "internet-exposed": "network_exposure",
    "encryption": "encryption",
    "logging": "logging_monitoring",
    "forensics-ready": "logging_monitoring",
    "identity-access": "access_control",
    "trustboundaries": "network_exposure",
    "secrets": "credential_risk",
}

# Prowler's CheckType TTP strings → CloudSentinel category (fallback).
TTP_CATEGORY_MAP: dict[str, str] = {
    "Initial Access": "network_exposure",
    "Credential Access": "credential_risk",
    "Privilege Escalation": "access_control",
    "Data Exposure": "data_exposure",
    "Data Exfiltration": "data_exposure",
    "Data Destruction": "data_exposure",
    "Persistence": "access_control",
    "Lateral Movement": "network_exposure",
    "Defense Evasion": "access_control",
    "Collection": "data_exposure",
    "Denial of Service": "network_exposure",
}

# Keywords in CheckType → short compliance-framework tag.
COMPLIANCE_KEYWORDS: dict[str, str] = {
    "CIS AWS Foundations Benchmark": "CIS",
    "AWS Foundational Security Best Practices": "AWS-FSBP",
    "PCI-DSS": "PCI-DSS",
    "SOC 2": "SOC2",
    "HIPAA Controls": "HIPAA",
    "NIST 800-53": "NIST-800-53",
    "NIST CSF": "NIST-CSF",
    "GDPR Controls": "GDPR",
    "ISO 27001": "ISO-27001",
}

# Compliance framework files to read for detailed control-level mappings.
# Maps filename → (display_name) used in output.
COMPLIANCE_FILES: dict[str, str] = {
    "cis_2.0_aws.json": "CIS-2.0",
    "cis_3.0_aws.json": "CIS-3.0",
    "aws_foundational_security_best_practices_aws.json": "AWS-FSBP",
    "pci_3.2.1_aws.json": "PCI-DSS-3.2.1",
    "pci_4.0_aws.json": "PCI-DSS-4.0",
    "soc2_aws.json": "SOC2",
    "hipaa_aws.json": "HIPAA",
    "nist_800_53_revision_5_aws.json": "NIST-800-53-r5",
    "nist_csf_2.0_aws.json": "NIST-CSF-2.0",
    "gdpr_aws.json": "GDPR",
    "iso27001_2022_aws.json": "ISO-27001-2022",
    "mitre_attack_aws.json": "MITRE-ATT&CK",
}


# ---------------------------------------------------------------------------
# Compliance reverse-map builder
# ---------------------------------------------------------------------------

def build_compliance_map(compliance_dir: Path) -> dict[str, list[dict[str, str]]]:
    """Build check_id → [{framework, version, control}] from framework files."""
    reverse: dict[str, list[dict[str, str]]] = {}

    for filename, display_name in COMPLIANCE_FILES.items():
        fpath = compliance_dir / filename
        if not fpath.exists():
            continue
        data = json.loads(fpath.read_text(encoding="utf-8"))
        framework = data.get("Framework", display_name)
        version = data.get("Version", "")

        for req in data.get("Requirements", []):
            control_id = req.get("Id", "")
            for check_id in req.get("Checks", []):
                entry = {
                    "framework": framework,
                    "version": version,
                    "control": control_id,
                }
                reverse.setdefault(check_id, []).append(entry)

    return reverse


# ---------------------------------------------------------------------------
# Category inference
# ---------------------------------------------------------------------------

def infer_category(metadata: dict[str, Any]) -> str:
    """Map Prowler metadata to a CloudSentinel finding category."""
    # 1. Try Prowler's own Categories field
    for cat in metadata.get("Categories", []):
        if cat in CATEGORY_MAP:
            return CATEGORY_MAP[cat]

    # 2. Try CheckType TTPs
    for ct in metadata.get("CheckType", []):
        for ttp_keyword, cs_cat in TTP_CATEGORY_MAP.items():
            if ttp_keyword in ct:
                return cs_cat

    # 3. Keyword inference from check ID
    check_id = metadata.get("CheckID", "").lower()
    keyword_rules: list[tuple[list[str], str]] = [
        (["encrypt", "kms", "ssl", "tls", "https"], "encryption"),
        (["log", "monitor", "trail", "flow_log", "cloudwatch"], "logging_monitoring"),
        (["public", "internet", "ingress", "exposed", "open_to"], "network_exposure"),
        (["iam", "policy", "role", "mfa", "password", "permission"], "access_control"),
        (["backup", "snapshot", "recovery", "replication", "versioning"], "backup_recovery"),
        (["secret", "credential", "access_key", "user_data"], "credential_risk"),
        (["tag", "unused", "orphan", "older_than", "not_used"], "resource_hygiene"),
    ]
    for keywords, category in keyword_rules:
        if any(kw in check_id for kw in keywords):
            return category

    return "compliance"


# ---------------------------------------------------------------------------
# Metadata extraction helpers
# ---------------------------------------------------------------------------

def extract_compliance_tags(check_types: list[str]) -> list[str]:
    """Extract short compliance framework tags from CheckType array."""
    tags: set[str] = set()
    for ct in check_types:
        for keyword, tag in COMPLIANCE_KEYWORDS.items():
            if keyword in ct:
                tags.add(tag)
    return sorted(tags)


def extract_mitre_tactics(check_types: list[str]) -> list[str]:
    """Extract MITRE ATT&CK tactics from CheckType TTP entries."""
    tactics: list[str] = []
    for ct in check_types:
        if ct.startswith("TTPs/"):
            tactics.append(ct.removeprefix("TTPs/"))
    return tactics


def determine_service(prowler_service: str, check_id: str) -> str:
    """Map Prowler service + check ID → CloudSentinel service name."""
    if prowler_service == "ec2":
        for prefix, cs_svc in EC2_SUBSERVICE_PREFIXES.items():
            if check_id.startswith(prefix):
                return cs_svc
    return PROWLER_TO_CS_SERVICE.get(prowler_service, prowler_service)


def transform_check(
    metadata: dict[str, Any],
    compliance_map: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    """Transform one Prowler check metadata into CloudSentinel format."""
    check_id = metadata["CheckID"]
    remediation = metadata.get("Remediation", {})
    code = remediation.get("Code", {})
    recommendation = remediation.get("Recommendation", {})
    check_types = metadata.get("CheckType", [])

    # Deduplicate compliance entries
    raw_compliance = compliance_map.get(check_id, [])
    seen: set[tuple[str, str, str]] = set()
    deduped_compliance: list[dict[str, str]] = []
    for entry in raw_compliance:
        key = (entry["framework"], entry["version"], entry["control"])
        if key not in seen:
            seen.add(key)
            deduped_compliance.append(entry)

    return {
        "id": check_id,
        "title": metadata.get("CheckTitle", ""),
        "severity": metadata.get("Severity", "medium"),
        "resource_type": metadata.get("ResourceType", ""),
        "category": infer_category(metadata),
        "description": metadata.get("Description", "").strip(),
        "risk": metadata.get("Risk", "").strip(),
        "remediation": {
            "cli": code.get("CLI", ""),
            "console_steps": code.get("Other", ""),
            "terraform": code.get("Terraform", "").strip().removeprefix("```hcl\n").removesuffix("\n```"),
            "cloudformation": code.get("NativeIaC", "").strip().removeprefix("```yaml\n").removesuffix("\n```"),
        },
        "recommendation": recommendation.get("Text", "").strip(),
        "reference_url": recommendation.get("Url", ""),
        "aws_doc_urls": [u for u in metadata.get("AdditionalURLs", []) if u],
        "compliance_tags": extract_compliance_tags(check_types),
        "compliance_details": deduped_compliance,
        "mitre_attack": extract_mitre_tactics(check_types),
        "prowler_categories": metadata.get("Categories", []),
    }


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------

def extract_all(prowler_root: Path) -> dict[str, list[dict[str, Any]]]:
    """Walk Prowler service dirs and extract all relevant checks."""
    services_dir = prowler_root / "prowler" / "providers" / "aws" / "services"
    compliance_dir = prowler_root / "prowler" / "compliance" / "aws"

    if not services_dir.exists():
        raise FileNotFoundError(f"Prowler services directory not found: {services_dir}")

    compliance_map = build_compliance_map(compliance_dir)

    service_checks: dict[str, list[dict[str, Any]]] = {}

    for prowler_service in sorted(PROWLER_TO_CS_SERVICE):
        svc_dir = services_dir / prowler_service
        if not svc_dir.exists():
            print(f"  [skip] {prowler_service}/ not found")
            continue

        for check_dir in sorted(svc_dir.iterdir()):
            if not check_dir.is_dir():
                continue
            metadata_files = list(check_dir.glob("*.metadata.json"))
            if not metadata_files:
                continue

            metadata = json.loads(metadata_files[0].read_text(encoding="utf-8"))
            check_id = metadata.get("CheckID", check_dir.name)
            cs_service = determine_service(prowler_service, check_id)
            check = transform_check(metadata, compliance_map)

            service_checks.setdefault(cs_service, []).append(check)

    return service_checks


def write_catalogs(service_checks: dict[str, list[dict[str, Any]]]) -> None:
    """Write one JSON file per service to OUTPUT_DIR."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for service, checks in sorted(service_checks.items()):
        # Sort checks: critical first, then high, medium, low, informational
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        checks.sort(key=lambda c: (severity_order.get(c["severity"], 5), c["id"]))

        output = {
            "service": service,
            "source": "prowler",
            "extraction_note": "Static metadata extracted from Prowler (Apache 2.0). No runtime dependency.",
            "check_count": len(checks),
            "checks": checks,
        }
        out_path = OUTPUT_DIR / f"{service}_checks.json"
        out_path.write_text(
            json.dumps(output, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"  {service:>5}: {len(checks):>3} checks → {out_path.name}")

    total = sum(len(c) for c in service_checks.values())
    print(f"\n  Total: {total} checks across {len(service_checks)} services")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prowler-root",
        type=Path,
        default=Path.home() / "Downloads" / "prowler",
        help="Path to the cloned Prowler repository (default: ~/Downloads/prowler)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    print(f"Extracting from: {args.prowler_root}")
    print(f"Output dir:      {OUTPUT_DIR}\n")

    service_checks = extract_all(args.prowler_root)
    write_catalogs(service_checks)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
