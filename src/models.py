"""
Core data models for Linux Hardening Checker.

This module contains the shared structures used by the scanner,
security checks, and reporting layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Numeric severity levels used for sorting and scoring."""

    PASS = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass(frozen=True, slots=True)
class Finding:
    """
    Represents one security audit finding.

    Attributes:
        check_id: Unique identifier for the check.
        title: Human-readable finding title.
        severity: Finding severity.
        message: Explanation of what was detected.
        recommendation: Suggested remediation.
        evidence: Optional technical evidence supporting the finding.
    """

    check_id: str
    title: str
    severity: Severity
    message: str
    recommendation: str = ""
    evidence: dict[str, Any] | None = None

    @property
    def is_issue(self) -> bool:
        """Return True when the finding represents a security issue."""
        return self.severity >= Severity.LOW

    @property
    def is_passing(self) -> bool:
        """Return True when the check passed."""
        return self.severity == Severity.PASS
