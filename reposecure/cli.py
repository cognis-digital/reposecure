"""Command-line interface for REPOSECURE."""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import grade_repo

_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def _render_table(report) -> str:
    lines: list[str] = []
    lines.append(f"REPOSECURE report card  —  {report.root}")
    lines.append("=" * 64)
    lines.append(f"  GRADE: {report.grade}   SCORE: {report.score}/100")
    lines.append("-" * 64)

    c = report.checks
    lines.append(
        f"  secrets : {c['secrets'].get('secrets_found', 0)} finding(s) "
        f"({c['secrets'].get('files_scanned', 0)} files scanned)"
    )
    lines.append(f"  ci      : {'present' if c['ci'].get('has_ci') else 'MISSING'}")
    lines.append(f"  branch  : {len(c['branch_rules'].get('signals', []))} protection signal(s)")
    lines.append(
        f"  deps    : {len(c['deps'].get('lockfiles', []))} lockfile(s), "
        f"{len(c['deps'].get('unpinned', []))} unpinned"
    )
    lines.append("-" * 64)

    if not report.findings:
        lines.append("  No findings. Clean posture.")
    else:
        lines.append(f"  {len(report.findings)} finding(s):")
        for f in report.findings:
            loc = f" [{f.path}:{f.line}]" if f.path else ""
            lines.append(f"  {_SEV_LABEL.get(f.severity, f.severity)}  {f.title}{loc}")
            lines.append(f"        {f.detail}")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="One-shot repository security posture grade "
                    "(secrets / CI / branch rules / deps). Defensive analysis only.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command")

    grade = sub.add_parser("grade", help="Grade a repository's security posture.")
    grade.add_argument("path", nargs="?", default=".",
                       help="Path to the repository (default: current directory).")
    grade.add_argument("--format", choices=["table", "json"], default="table",
                       help="Output format (default: table).")
    grade.add_argument("--min-grade", default=None,
                       help="Fail (exit 2) if grade is worse than this letter (A-F).")
    return parser


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "grade":
        try:
            report = grade_repo(args.path)
        except (NotADirectoryError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(_render_table(report))

        # Exit policy: non-zero when findings exist or grade gate fails.
        if args.min_grade:
            order = "ABCDF"
            want = args.min_grade.upper()
            if want in order and order.index(report.grade) > order.index(want):
                return 2
        if report.findings:
            return 2
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
