# Validation record

Initial implementation, October 24, 2026.

This is a historical record. See [the latest review and validation](FULL_REVIEW_2026-10-25.md) and [subsequent remediation](REVIEW_FIXES.md) for current coverage, including Docker/Caddy startup, MySQL, real SSH fixtures and restic recovery CI.

## Executed successfully

- **29 pytest tests** covering authentication/CSRF, personalized offline installer shell/Python syntax, enrollment-link expiry, unsafe repository rejection, inventory and package holds, exact-version patch jobs, SSH host fingerprint pinning, TLS domain/key checks, AI request minimization and explicit trust approval, backoff, target JSON-command validation, atomic-write symlink rejection, and process identity normalization.
- Real native APT integration against a locally served, signed ARM64 repository: discovers a newer candidate; rejects altered index bytes; rejects altered signed Release content. The test generates an ephemeral OpenPGP key and never contacts a user's target.
- Python compilation for the application and target scripts.
- JavaScript syntax check and shell syntax check for the Docker entrypoint.
- Chromium/Playwright desktop and mobile smoke checks: login, overview, create enrollment, generate curl link, open settings, and mobile navigation. **No browser JavaScript exceptions; no page-level horizontal overflow at 390px.**
- Manual visual review of desktop overview, settings, and mobile screenshots.
- **GitHub Actions passed** for implementation commit `7e45cdcd6cec4710c84468d61eb35bf862e585a3`, including pytest, compilation/syntax checks, Compose configuration validation, and Docker image build. [Successful run](https://github.com/StealthCat/MrPatchy/actions/runs/40148567352).

## Not executed in the development workspace

- A full running Docker Compose deployment: Docker was unavailable locally. The image build and Compose configuration were validated successfully in GitHub Actions, but service startup/end-to-end networking were not exercised there.
- Actual systemd target enrollment, reboot persistence, sudo/SSH execution on a real Ubuntu/Raspberry Pi OS host, or a live package upgrade.
- Live MySQL connection/migration.
- Caddy runtime reload or real ACME certificate issuance; TLS validation and generated configuration boundaries were tested with a mocked Caddy endpoint.
- Paid OpenAI API calls: request shape, redaction, output handling and approval boundaries were tested with mocked responses.
- Large-fleet load/soak testing, adversarial penetration testing, or recovery from a compromised kernel/root account.

These are explicit deployment-validation gaps, not passed tests. Begin with a disposable Ubuntu VM and a spare Raspberry Pi, review package/source changes, and back up before patching important services.

## Reproduction

```bash
pip install -r requirements-dev.txt
python -m pytest -q
python -m compileall -q app target
node --check app/static/app.js
bash -n deploy/entrypoint.sh
```

The signed-repository test requires native `apt-get`, `apt-cache`, `dpkg`, and GnuPG tooling. Its Python signing helper is test-only. Two dependency deprecation warnings were observed (Starlette TestClient HTTP transport and PGPy's use of imghdr); they did not fail tests.

Browser checks can be repeated with `npm install`, `npx playwright install --with-deps chromium`, and `npm run test:ui`. The test creates a temporary local database and a documentation-only server address; it never deploys to that address. Screenshots in `docs/screenshots` are from the actual UI, not design mockups.
