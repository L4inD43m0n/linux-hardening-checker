#!/usr/bin/env python3

"""
Linux Hardening Checker
=======================

A lightweight, read-only Linux security auditing utility.

The checker inspects selected system configurations and reports
potential hardening issues without modifying the target system.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    """Severity levels used by audit findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    PASS = "PASS"


@dataclass(frozen=True)
class Finding:
    """Represents the result of a single security check."""

    check_id: str
    title: str
    severity: Severity
    message: str
    recommendation: str = ""


SENSITIVE_FILES: tuple[tuple[str, int, Severity], ...] = (
    ("/etc/passwd", 0o644, Severity.HIGH),
    ("/etc/shadow", 0o640, Severity.CRITICAL),
    ("/etc/group", 0o644, Severity.MEDIUM),
)


def permission_bits(path: Path) -> int:
    """Return only the UNIX permission bits for a file."""
    return stat.S_IMODE(path.stat().st_mode)


def format_mode(mode: int) -> str:
    """Format a UNIX permission mode as an octal string."""
    return f"{mode:04o}"


def check_file_permissions() -> list[Finding]:
    """
    Audit permissions on selected sensitive Linux system files.

    This check is read-only and does not change file permissions.
    """
    findings: list[Finding] = []

    for raw_path, recommended_mode, severity in SENSITIVE_FILES:
        path = Path(raw_path)

        if not path.exists():
            findings.append(
                Finding(
                    check_id="FS-001",
                    title=f"Sensitive file unavailable: {path}",
                    severity=Severity.INFO,
                    message="The expected file does not exist on this system.",
                )
            )
            continue

        try:
            current_mode = permission_bits(path)
        except PermissionError:
            findings.append(
                Finding(
                    check_id="FS-002",
                    title=f"Cannot inspect: {path}",
                    severity=Severity.MEDIUM,
                    message="Permission was denied while reading file metadata.",
                    recommendation="Run the audit with appropriate read permissions.",
                )
            )
            continue
        except OSError as exc:
            findings.append(
                Finding(
                    check_id="FS-003",
                    title=f"Inspection error: {path}",
                    severity=Severity.MEDIUM,
                    message=f"Unable to read file metadata: {exc}",
                )
            )
            continue

        recommended_mask = recommended_mode
        unexpected_bits = current_mode & ~recommended_mask

        if unexpected_bits:
            findings.append(
                Finding(
                    check_id="FS-004",
                    title=f"Permissions need review: {path}",
                    severity=severity,
                    message=(
                        f"Current mode is {format_mode(current_mode)}; "
                        f"recommended baseline is {format_mode(recommended_mode)}."
                    ),
                    recommendation=(
                        "Review the file permissions and apply the least-privilege "
                        "configuration appropriate for the system."
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="FS-005",
                    title=f"Permissions OK: {path}",
                    severity=Severity.PASS,
                    message=(
                        f"Current mode {format_mode(current_mode)} "
                        f"matches the defined baseline."
                    ),
                )
            )

    return findings


def check_root_account() -> list[Finding]:
    """Check whether a root account entry exists in /etc/passwd."""
    passwd_file = Path("/etc/passwd")

    if not passwd_file.exists():
        return [
            Finding(
                check_id="USR-001",
                title="Root account check unavailable",
                severity=Severity.INFO,
                message="/etc/passwd was not found.",
            )
        ]

    try:
        lines = passwd_file.read_text(encoding="utf-8").splitlines()
    except (PermissionError, OSError) as exc:
        return [
            Finding(
                check_id="USR-002",
                title="Unable to inspect root account",
                severity=Severity.MEDIUM,
                message=f"Could not read /etc/passwd: {exc}",
            )
        ]

    root_entries = [
        line for line in lines
        if line and not line.startswith("#") and line.split(":", 1)[0] == "root"
    ]

    if root_entries:
        return [
            Finding(
                check_id="USR-003",
                title="Root account exists",
                severity=Severity.INFO,
                message="A standard root account entry was found.",
                recommendation=(
                    "Ensure direct root access is restricted and administrative "
                    "work is performed through controlled privilege escalation."
                ),
            )
        ]

    return [
        Finding(
            check_id="USR-004",
            title="Root account entry not found",
            severity=Severity.HIGH,
            message="The expected root account entry was not found.",
        )
    ]


def run_audit() -> list[Finding]:
    """Run all currently available security checks."""
    findings: list[Finding] = []

    findings.extend(check_file_permissions())
    findings.extend(check_root_account())

    return findings


def severity_rank(severity: Severity) -> int:
    """Return a sortable numeric value for a severity."""
    ranking = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
        Severity.PASS: 0,
    }

    return ranking[severity]


def calculate_score(findings: list[Finding]) -> int:
    """
    Calculate a simple security score from findings.

    The score is intentionally conservative and intended for
    relative audit visibility rather than compliance certification.
    """
    deductions = {
        Severity.CRITICAL: 30,
        Severity.HIGH: 20,
        Severity.MEDIUM: 10,
        Severity.LOW: 5,
        Severity.INFO: 0,
        Severity.PASS: 0,
    }

    score = 100

    for finding in findings:
        score -= deductions[finding.severity]

    return max(score, 0)


def print_header() -> None:
    """Print the application header."""
    print("=" * 72)
    print(" Linux Hardening Checker")
    print(" Read-only Linux security configuration audit")
    print("=" * 72)


def print_findings(findings: list[Finding]) -> None:
    """Print findings in severity order."""
    ordered = sorted(
        findings,
        key=lambda item: severity_rank(item.severity),
        reverse=True,
    )

    for finding in ordered:
        print(
            f"\n[{finding.severity.value}] "
            f"{finding.check_id} - {finding.title}"
        )
        print(f"  {finding.message}")

        if finding.recommendation:
            print(f"  Recommendation: {finding.recommendation}")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run a read-only Linux security hardening audit."
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only display the final security score.",
    )

    return parser.parse_args()


def main() -> int:
    """Application entry point."""
    args = parse_args()

    if os.name != "posix":
        print(
            "[ERROR] This tool currently supports POSIX/Linux systems.",
            file=sys.stderr,
        )
        return 1

    findings = run_audit()
    score = calculate_score(findings)

    if not args.quiet:
        print_header()
        print_findings(findings)

        print("\n" + "-" * 72)
        print(f" Security Score: {score}/100")
        print(f" Checks Run:     {len(findings)}")
        print("-" * 72)

    else:
        print(score)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
