# SecureSense: Release Checklist

## 1. Purpose

Use this checklist to prepare, review, and release SecureSense without
confusing successful local validation with a completed hosted release.

**Current release state:** Version `v0.1.0` is published on GitHub, and its
release page and initial hosted CI evidence have been recorded. The changes
currently under review are an unreleased update; they must pass final acceptance,
receive explicit approval, and be pushed before the new version can be called
released.

Do not mark a step complete until its evidence has been observed.

## 2. Local validation

- [x] Automated test suite: 211 passed in the latest recorded full run (1 deprecation warning).
- [x] Ruff: all checks passed.
- [x] Dependency lock check: `uv lock --check` passed.
- [x] Five manual investigation scenarios executed successfully.
- [x] README updated with setup instructions and scenario guide.
- [x] Project build and validation journey documented.
- [x] Architecture and threat model documented.
- [x] Docker image build and sample execution verified previously.
- [x] Wokwi serial-output replay through the MQTT bridge and a local
      subscriber verified previously.
- [ ] Review and resolve the recorded Starlette/httpx deprecation warning
      in a separate dependency change if needed.

The Docker and MQTT checks above refer to previously recorded results and
must not be interpreted as having been rerun during the latest test suite.

## 3. Documentation review

- [ ] Check all commands against the current CLI and API.
- [ ] Verify Markdown fences, relative links, headings, and file paths.
- [ ] Ensure generated reports, local logs, credentials, and local executables
      are not accidentally included in the release.
- [ ] Ensure synthetic scenarios and security limitations are described honestly.
- [ ] Review this checklist after each actual release step.
- [x] Confirmed `README.md.backup` is not present in the repository.

## 4. Repository review before staging

From Git Bash, run:

```bash id="ktp7ps"
cd /d/SecureSense

git status --short
git check-ignore -v reports/ wokwi/wokwi-cli.exe
git diff --check
uv run pytest -v
uv run ruff check src tests
uv lock --check
```

Review the output and confirm that ignored local artifacts are excluded and
all intended source, tests, configuration, scenario, and documentation files
are present.

Because newly created files are untracked, `git diff --check` alone does not
validate their contents. Inspect them directly and review the staged diff
after staging.

## 5. Staging and commit review

**Do not stage, commit, or push until the repository owner explicitly approves.**

After approval:

1. Stage only the intended project files.
2. Run `git status --short` and inspect every staged path.
3. Run `git diff --cached --check`.
4. Review the complete staged diff with `git diff --cached`.
5. Confirm there are no credentials, local binaries, generated reports, or
   unrelated files.
6. Confirm the README and all three documents are included.
7. Create a descriptive commit only after the staged diff is approved.
8. Record the actual commit identifier and commit message.

Do not fabricate commit identifiers or report a commit that has not happened.

## 6. Push and hosted CI verification

After the commit is reviewed and push approval is given:

1. Confirm the intended GitHub repository and remote URL.
2. Confirm the destination branch before pushing.
3. Push only the approved commit to the intended remote.
4. Open the repository's Actions page.
5. Confirm the workflow ran for the pushed commit.
6. Record whether dependency installation, Ruff, and pytest passed.
7. Investigate and fix any failure, then rerun the checks.
8. Do not claim hosted CI success until the actual run is successful.

Recorded initial publication evidence:

- Repository URL: https://github.com/SriKrishna40007/SecureSense
- Branch: master
- Commit identifier: 65f508fbb8c73ae3c7b2b7f20cd9478da2b986a1
- Push date: 2026-10-12
- GitHub Actions run: https://github.com/SriKrishna40007/SecureSense/actions/runs/38269152038
- Hosted CI result: success (SecureSense CI)
- Versioned GitHub Release: v0.1.0
- Release URL: https://github.com/SriKrishna40007/SecureSense/releases/tag/v0.1.0

## 7. Optional release tag

Create a release tag only if a deliberate versioned release is needed and the
repository owner approves it.

If a tag is created, record the exact tag and the commit it references. Do
not imply that a tag exists before it has actually been created and verified.

## 8. Known limitations to disclose

- Events in the supplied investigation scenarios are synthetic.
- Risk scores are configured severity-based scores, not probabilities.
- Candidate attack paths require analyst validation.
- Response recommendations are dry-run records; no enforcement is executed.
- Investigations, incidents and lifecycle audit history, sensor readings, and event-deduplication records are persisted in SQLite; API restart persistence has been verified locally.
- MQTT sensor telemetry is not automatically converted into network-security events; valid messages on the dedicated network-event topic are automatically investigated.
- The local MQTT broker requires authentication but has no TLS configured; keep it confined to the local lab environment.
- Hosted CI passed for the initial commit; verify CI again for subsequent release commits.

## 9. Final release acceptance

A release is ready to be described as verified only when:

- Local tests, lint, and lock checks pass.
- Documentation and repository contents have been reviewed.
- The approved commit has been created.
- The approved push has completed.
- Hosted CI has passed for the intended commit.
- Actual release evidence has been recorded.

Until then, describe the project as locally validated and release preparation
in progress.

## 10. Related documentation

- [Project README](../README.md)
- [Project build and validation journey](PROJECT_BUILD_AND_VALIDATION.md)
- [Architecture and threat model](ARCHITECTURE_AND_THREAT_MODEL.md)
