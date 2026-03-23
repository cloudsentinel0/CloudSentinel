from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from check_loader import build_check_reference, format_check_reference
from scan_parser import ParsedScan, parse_scan_file


BASE_DIR = Path(__file__).resolve().parent          # backend/
PROJECT_ROOT = BASE_DIR.parent                       # CloudSentinel/
SKILLS_DIR = BASE_DIR / "skills"

AGENTS_PATH = PROJECT_ROOT / "AGENTS.md"
CLAUDE_PATH = PROJECT_ROOT / "CLAUDE.md"
COMMON_PATTERNS_PATH = PROJECT_ROOT / "common_patterns.md"
SERVICE_SKILL_PATHS = {
    "ec2": SKILLS_DIR / "ec2_skill.md",
    "s3": SKILLS_DIR / "s3_skill.md",
    "iam": SKILLS_DIR / "iam_skill_improved.md",
    "vpc": SKILLS_DIR / "vpc_skill_improved.md",
    "rds": SKILLS_DIR / "rds_skill.md",
    "ebs": SKILLS_DIR / "ebs_skill.md",
    "ami": SKILLS_DIR / "ami_skill.md",
    "elb": SKILLS_DIR / "elb_skill.md",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a generic LLM-ready CloudSentinel analysis bundle."
    )
    parser.add_argument("--scan-file", required=True, help="Path to scanner output text.")
    parser.add_argument(
        "--output-file",
        help="Optional path to write the analysis bundle JSON.",
    )
    parser.add_argument(
        "--include-raw-text",
        action="store_true",
        help="Include the full raw scan text in the embedded parsed scan payload.",
    )
    parser.add_argument(
        "--include-raw-command-bodies",
        action="store_true",
        help="Include each raw command body in the embedded parsed scan payload.",
    )
    return parser.parse_args()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def get_contract_prompt_path() -> Path:
    if AGENTS_PATH.exists():
        return AGENTS_PATH
    if CLAUDE_PATH.exists():
        return CLAUDE_PATH
    raise FileNotFoundError("Neither AGENTS.md nor CLAUDE.md was found.")


def get_service_skill_path(primary_service: str) -> Path:
    try:
        return SERVICE_SKILL_PATHS[primary_service]
    except KeyError as exc:
        raise ValueError(f"Unsupported primary service: {primary_service}") from exc


def make_scan_summary(parsed_scan: ParsedScan) -> dict[str, Any]:
    return {
        "primary_service": parsed_scan.primary_service,
        "scan_timestamp": parsed_scan.scan_timestamp,
        "section_count": len(parsed_scan.sections),
        "dependency_services": parsed_scan.dependency_services,
        "total_commands": parsed_scan.total_commands,
        "total_error_commands": parsed_scan.total_error_commands,
    }


def compose_user_prompt(
    *,
    primary_service: str,
    common_patterns_text: str,
    service_skill_text: str,
    check_reference_text: str,
    parsed_scan_payload: dict[str, Any],
) -> str:
    evidence_json = json.dumps(parsed_scan_payload, separators=(",", ":"), sort_keys=True)

    parts: list[str] = [
        f"Primary service: {primary_service}\n",
        "Follow the CloudSentinel contract from your system instructions. "
        "Use the common patterns, service skill, and check catalog below as supporting analysis guidance. "
        "Analyze only the scanned scope. Return valid JSON only.\n",
        "=== COMMON PATTERNS ===\n"
        f"{common_patterns_text.strip()}\n",
        "=== PRIMARY SERVICE SKILL ===\n"
        f"{service_skill_text.strip()}\n",
    ]

    if check_reference_text:
        parts.append(
            "=== CHECK CATALOG REFERENCE ===\n"
            f"{check_reference_text}\n"
        )

    parts.append(
        "=== PARSED SCAN EVIDENCE JSON ===\n"
        f"{evidence_json}\n"
    )

    return "\n".join(parts)


def build_analysis_bundle(
    parsed_scan: ParsedScan,
    *,
    scan_source: str,
    include_raw_text: bool = False,
    include_raw_command_bodies: bool = False,
) -> dict[str, Any]:
    contract_path = get_contract_prompt_path()
    contract_text = read_text(contract_path)
    common_patterns_text = read_text(COMMON_PATTERNS_PATH)
    service_skill_path = get_service_skill_path(parsed_scan.primary_service)
    service_skill_text = read_text(service_skill_path)
    parsed_scan_payload = parsed_scan.to_dict(
        include_raw_text=include_raw_text,
        include_raw_bodies=include_raw_command_bodies,
    )

    # Load check catalog for primary + dependency services
    check_ref = build_check_reference(
        parsed_scan.primary_service,
        dependency_services=parsed_scan.dependency_services,
    )
    check_reference_text = format_check_reference(check_ref)

    contract_files: dict[str, str] = {
        "contract": str(contract_path),
        "common_patterns": str(COMMON_PATTERNS_PATH),
        "service_skill": str(service_skill_path),
    }
    if AGENTS_PATH.exists():
        contract_files["agents"] = str(AGENTS_PATH)
    if CLAUDE_PATH.exists():
        contract_files["claude"] = str(CLAUDE_PATH)

    return {
        "service": parsed_scan.primary_service,
        "scan_source": scan_source,
        "scan_summary": make_scan_summary(parsed_scan),
        "contract_files": contract_files,
        "parsed_scan": parsed_scan_payload,
        "llm_request": {
            "response_format": "json_object",
            "system_prompt": contract_text,
            "user_prompt": compose_user_prompt(
                primary_service=parsed_scan.primary_service,
                common_patterns_text=common_patterns_text,
                service_skill_text=service_skill_text,
                check_reference_text=check_reference_text,
                parsed_scan_payload=parsed_scan_payload,
            ),
        },
    }


def write_output(payload: dict[str, Any], output_file: str | None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if output_file:
        Path(output_file).write_text(rendered + "\n", encoding="utf-8")
        return
    print(rendered)


def main() -> int:
    args = parse_args()
    parsed_scan = parse_scan_file(args.scan_file)
    bundle = build_analysis_bundle(
        parsed_scan,
        scan_source=str(Path(args.scan_file).resolve()),
        include_raw_text=args.include_raw_text,
        include_raw_command_bodies=args.include_raw_command_bodies,
    )
    write_output(bundle, args.output_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
