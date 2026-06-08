"""Smoke tests for REPOSECURE. No network."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import reposecure  # noqa: E402
from reposecure.cli import main  # noqa: E402
from reposecure.core import grade_repo, score_to_letter  # noqa: E402


def _make_repo(tmp_path):
    (tmp_path / "config.py").write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
        'token = "your-token-here"\n',  # placeholder -> ignored
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("requests\nflask==3.0.0\n", encoding="utf-8")
    return tmp_path


def test_exports():
    assert reposecure.TOOL_NAME == "reposecure"
    assert reposecure.TOOL_VERSION
    assert callable(reposecure.grade_repo)


def test_score_to_letter():
    assert score_to_letter(100) == "A"
    assert score_to_letter(85) == "B"
    assert score_to_letter(0) == "F"


def test_clean_repo_scores_high(tmp_path):
    (tmp_path / "src.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}\n", encoding="utf-8")
    os.makedirs(tmp_path / ".github" / "workflows")
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("on: push\n", encoding="utf-8")
    (tmp_path / "CODEOWNERS").write_text("* @team\n", encoding="utf-8")
    (tmp_path / ".github" / "pull_request_template.md").write_text("checklist\n", encoding="utf-8")
    report = grade_repo(str(tmp_path))
    assert report.grade in ("A", "B")
    assert report.score >= 80


def test_secret_detection_and_placeholder_ignored(tmp_path):
    repo = _make_repo(tmp_path)
    report = grade_repo(str(repo))
    secrets = [f for f in report.findings if f.check == "secrets"]
    assert any(f.severity == "critical" for f in secrets)
    # placeholder token must NOT be flagged
    assert all("your-token-here" not in f.detail for f in secrets)
    assert report.grade == "F"


def test_json_round_trip(tmp_path):
    report = grade_repo(str(_make_repo(tmp_path)))
    blob = json.dumps(report.to_dict())
    data = json.loads(blob)
    assert data["score"] == report.score
    assert "findings" in data and isinstance(data["findings"], list)


def test_cli_json_nonzero_exit(tmp_path, capsys):
    repo = _make_repo(tmp_path)
    rc = main(["grade", str(repo), "--format", "json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["grade"] == "F"
    assert rc == 2  # findings present -> non-zero


def test_cli_no_command_returns_one(capsys):
    rc = main([])
    assert rc == 1


def test_version_flag():
    proc = subprocess.run(
        [sys.executable, "-m", "reposecure", "--version"],
        capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    assert "reposecure" in proc.stdout
    assert proc.returncode == 0
