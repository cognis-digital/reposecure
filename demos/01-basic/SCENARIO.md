# Demo 01 — Basic repo security grade

This scenario shows REPOSECURE grading a small, deliberately-flawed repository
checkout under `sample_repo/`.

## The sample repo

`sample_repo/` contains intentional posture problems for a **defensive demo**:

- `config.py` — embeds a hard-coded AWS access key id and a private key block
  (the exact strings are obviously fake, but match real high-signal patterns).
- `requirements.txt` — has unpinned dependencies and no lockfile.
- No CI workflow, no `CODEOWNERS`, no PR template.

## Run it

From the directory that contains the `reposecure` package:

```sh
python -m reposecure grade demos/01-basic/sample_repo --format table
python -m reposecure grade demos/01-basic/sample_repo --format json
```

## Expected outcome

- **Grade: F** (multiple critical secret findings drive the score to 0).
- Findings list two critical secrets, a missing-CI medium, missing
  branch-protection signals (low), and unpinned-deps / no-lockfile (medium).
- Process exits with code **2** because findings are present — making the tool
  usable as a CI gate (`reposecure grade . --min-grade B`).

This is detection / triage only: REPOSECURE reads files and reports posture.
It performs no network calls and takes no action against any system.
