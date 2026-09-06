#!/usr/bin/env python3

"""
Linux Hardening Checker

A lightweight, non-destructive Linux security auditing utility.
"""

from pathlib import Path


def check_sensitive_files() -> None:
    """Check permissions of a few sensitive system files."""
    targets = [
        Path("/etc/passwd"),
        Path("/etc/shadow"),
        Path("/etc/ssh/sshd_config"),
    ]

    print("\n[+] Sensitive File Permissions")

    for target in targets:
        if not target.exists():
            print(f"[-] {target}: not found")
            continue

        try:
            mode = target.stat().st_mode & 0o777
            print(f"[INFO] {target}: {oct(mode)}")
        except PermissionError:
            print(f"[WARN] {target}: permission denied")


def main() -> None:
    print("=" * 60)
    print("Linux Hardening Checker")
    print("=" * 60)

    check_sensitive_files()


if __name__ == "__main__":
    main()
