"""Core engine for REPOSECURE.

Grades a repository's security posture across four checks:
  1. Secrets         — high-signal credential patterns in tracked files.
  2. CI              — presence of a CI workflow / pipeline definition.
  3. Branch rules    — signals of branch protection / required review.
  4. Dependencies    — lockfiles + pinned vs. unpinned dependencies.

Pure standard library. No network. Read-only filesystem access.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, asdict
from typing import Iterable

# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #

SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 20,
    "medium": 8,
    "low": 3,
    "info": 0,
}

# Files / directories we never want to scan for content.
SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".mypy_cache", ".pytest_cache", "vendor",
    ".idea", ".vscode", "target", "site-packages",
}
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".7z", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
    ".so", ".dll", ".dylib", ".class", ".jar", ".pyc", ".bin",
    ".lock",  # large lockfiles are scanned separately for deps, not secrets
}
MAX_FILE_BYTES = 1_000_000  # skip files larger than ~1MB for secret scan


# --------------------------------------------------------------------------- #
# Secret detectors — high-signal, low false-positive patterns.
# --------------------------------------------------------------------------- #

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("GitHub Personal Access Token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "critical"),
    ("GitHub OAuth Token", re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "critical"),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"), "critical"),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical"),
    ("Generic Bearer/Auth assignment",
     re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"), "medium"),
]

# Values that look like placeholders, not real secrets.
PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]?|example|changeme|placeholder|xxxx|<.*?>|dummy|test[_-]?key|sample|redacted|fake)"
)


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str
    path: str = ""
    line: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    root: str
    score: int
    grade: str
    findings: list[Finding] = field(default_factory=list)
    checks: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "score": self.score,
            "grade": self.grade,
            "findings": [f.to_dict() for f in self.findings],
            "checks": self.checks,
        }


def score_to_letter(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


# --------------------------------------------------------------------------- #
# Filesystem walking
# --------------------------------------------------------------------------- #

def _iter_files(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


def _rel(root: str, path: str) -> str:
    try:
        return os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        return path


# --------------------------------------------------------------------------- #
# Check 1: secrets
# --------------------------------------------------------------------------- #

def _scan_secrets(root: str) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    files_scanned = 0
    for path in _iter_files(root):
        ext = os.path.splitext(path)[1].lower()
        if ext in SKIP_EXTS:
            continue
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        files_scanned += 1
        rel = _rel(root, path)
        for lineno, text in enumerate(lines, start=1):
            for name, pattern, severity in SECRET_PATTERNS:
                m = pattern.search(text)
                if not m:
                    continue
                matched = m.group(0)
                # Only suppress placeholders for the low-confidence generic
                # assignment rule; structured high-signal patterns (AWS/GitHub/
                # Stripe/private-key) are reported even if they look example-ish.
                if severity == "medium" and (
                    PLACEHOLDER_RE.search(matched) or PLACEHOLDER_RE.search(text)
                ):
                    continue
                findings.append(Finding(
                    check="secrets",
                    severity=severity,
                    title=f"Possible {name}",
                    detail=f"Matched pattern on line {lineno}",
                    path=rel,
                    line=lineno,
                ))
    meta = {"files_scanned": files_scanned, "secrets_found": len(findings)}
    return findings, meta


# --------------------------------------------------------------------------- #
# Check 2: CI
# --------------------------------------------------------------------------- #

CI_MARKERS = [
    ".github/workflows",
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
    ".circleci/config.yml",
    "Jenkinsfile",
    ".travis.yml",
    "bitbucket-pipelines.yml",
]


def _check_ci(root: str) -> tuple[list[Finding], dict]:
    found = []
    for marker in CI_MARKERS:
        p = os.path.join(root, marker.replace("/", os.sep))
        if os.path.exists(p):
            if os.path.isdir(p):
                if any(os.scandir(p)):
                    found.append(marker)
            else:
                found.append(marker)
    findings: list[Finding] = []
    if not found:
        findings.append(Finding(
            check="ci",
            severity="medium",
            title="No CI pipeline detected",
            detail="No CI configuration found; automated build/test/security gates are absent.",
        ))
    return findings, {"ci_systems": found, "has_ci": bool(found)}


# --------------------------------------------------------------------------- #
# Check 3: branch protection signals
# --------------------------------------------------------------------------- #

def _check_branch_rules(root: str) -> tuple[list[Finding], dict]:
    signals: list[str] = []
    # CODEOWNERS enforces review routing.
    for loc in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
        if os.path.exists(os.path.join(root, loc.replace("/", os.sep))):
            signals.append(loc)
            break
    # PR template signals a review process.
    for loc in (".github/pull_request_template.md", ".github/PULL_REQUEST_TEMPLATE.md"):
        if os.path.exists(os.path.join(root, loc.replace("/", os.sep))):
            signals.append("pull_request_template")
            break
    # Dependabot / renovate keep deps reviewed.
    for loc in (".github/dependabot.yml", "renovate.json", ".renovaterc"):
        if os.path.exists(os.path.join(root, loc.replace("/", os.sep))):
            signals.append("automated_dep_review")
            break

    findings: list[Finding] = []
    if "CODEOWNERS" not in " ".join(signals):
        findings.append(Finding(
            check="branch_rules",
            severity="low",
            title="No CODEOWNERS file",
            detail="Without CODEOWNERS, required-review routing for sensitive paths is not enforced.",
        ))
    if not any(s == "pull_request_template" for s in signals):
        findings.append(Finding(
            check="branch_rules",
            severity="low",
            title="No pull request template",
            detail="A PR template helps enforce review/security checklists on changes.",
        ))
    return findings, {"signals": signals}


# --------------------------------------------------------------------------- #
# Check 4: dependencies
# --------------------------------------------------------------------------- #

LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "Pipfile.lock", "Cargo.lock",
    "go.sum", "composer.lock", "Gemfile.lock",
}
MANIFESTS = {"requirements.txt", "package.json", "pyproject.toml", "Pipfile"}

_UNPINNED_REQ = re.compile(r"^\s*([A-Za-z0-9._\-]+)\s*$")  # bare name, no version


def _check_deps(root: str) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    lockfiles_found: list[str] = []
    manifests_found: list[str] = []
    unpinned: list[str] = []

    for path in _iter_files(root):
        base = os.path.basename(path)
        rel = _rel(root, path)
        if base in LOCKFILES:
            lockfiles_found.append(rel)
        if base in MANIFESTS:
            manifests_found.append(rel)
        if base == "requirements.txt":
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    for raw in fh:
                        line = raw.split("#", 1)[0].strip()
                        if not line or line.startswith("-"):
                            continue
                        # pinned if it contains a version specifier
                        if not re.search(r"[=<>~!@]", line):
                            unpinned.append(f"{rel}:{line}")
            except OSError:
                continue

    if manifests_found and not lockfiles_found:
        findings.append(Finding(
            check="deps",
            severity="medium",
            title="No dependency lockfile",
            detail="Manifests present but no lockfile; builds are not reproducible and supply-chain pinning is weak.",
        ))
    if unpinned:
        findings.append(Finding(
            check="deps",
            severity="medium",
            title=f"{len(unpinned)} unpinned dependency(ies)",
            detail="Unpinned dependencies allow silent upstream changes: " + ", ".join(unpinned[:10]),
        ))

    return findings, {
        "lockfiles": lockfiles_found,
        "manifests": manifests_found,
        "unpinned": unpinned,
    }


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def grade_repo(root: str) -> Report:
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise NotADirectoryError(f"Not a directory: {root}")

    all_findings: list[Finding] = []
    checks: dict = {}

    for name, fn in (
        ("secrets", _scan_secrets),
        ("ci", _check_ci),
        ("branch_rules", _check_branch_rules),
        ("deps", _check_deps),
    ):
        findings, meta = fn(root)
        all_findings.extend(findings)
        checks[name] = meta

    penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in all_findings)
    score = max(0, 100 - penalty)
    grade = score_to_letter(score)

    # Sort findings worst-first for readability.
    order = {s: i for i, s in enumerate(["critical", "high", "medium", "low", "info"])}
    all_findings.sort(key=lambda f: (order.get(f.severity, 99), f.check, f.path, f.line))

    return Report(root=root, score=score, grade=grade, findings=all_findings, checks=checks)
