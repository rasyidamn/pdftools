# PDF Merge Gateway

Internal web app that merges many PDFs of company documents. Runs on the local network only, simple GUI for
non-technical staff, SSO with Active Directory, and a complete audit log (who, which files, success or failure).

## Commands (run from `api/`, not the repo root)

```powershell
cd api
uv sync                # install from pyproject.toml + uv.lock (`uv sync --frozen` on the VM/Docker)
uv run pytest -q       # all tests
uv add <package>       # add a dependency; never edit uv.lock by hand
```

Python 3.13. Commit `pyproject.toml` and `uv.lock` together.

Deploy (repo root, on the VM): `cp .env.example .env`, fill it in, `docker compose up -d --build`. Full IIS/firewall/
backup steps and the on-VM test checklist are in `docs/deploy.md`. Front end lives in `api/app/static/`
(`common.js` shared helpers; `tests/test_static.py` enforces the CSP/`textContent` rules).

## Architecture

```
Domain PC → IIS (Windows Auth, AD group check, URL Rewrite + ARR)
          → Linux VM, Docker Compose: api (FastAPI, only published port) · stirling (no port) · db (PostgreSQL, no port)
```

- FastAPI does **not** authenticate. IIS sets `X-Remote-User` (`DOMAIN\user`) and `X-Gateway-Secret`; FastAPI trusts
  the user header only if the secret matches.
- Client IP = the **rightmost** `X-Forwarded-For` entry (left entries can be forged).
- The merge engine sits behind the `MergeEngine` interface (`api/app/engine/`): `stirling` (default) or `pypdf`.
- `main.py` is one `create_app()`; the order inside is gateway/health → merge → admin → static mount.

## Rules that must not be broken

1. **Fail closed.** Write the `SUCCESS` audit row BEFORE handing over the PDF (`audit_required`); on failure return 503
   and no file. Admin reads (`AUDIT_VIEW/EXPORT/VERIFY`) are logged first too. `REJECTED`/`FAILED` are best effort.
2. **Audit is append-only.** App DB account = SELECT + INSERT only; triggers reject UPDATE/DELETE/TRUNCATE.
   Never write code that edits or deletes audit rows. Hash chain: `prev_hash` + `payload_json` → sha256.
3. **No header is trusted without the secret.** Every route except `/api/health` passes `gateway_guard`.
4. **Clean user text.** File names go through `clean_text` before the audit; the front end uses `textContent` only
   (a test forbids `innerHTML`, `eval`).
5. **Strict CSP.** No inline script or style; put them in files under `api/app/static/`.
6. **CSV export** prefixes cells starting with `= + - @ \t \r` with `'`.
7. **Never show engine internals to staff.** Staff get a friendly message + short code; details go to the audit.
8. **Verify engine output.** Result page count must equal total input pages, else `OUTPUT_MISMATCH`; each page's
   mediabox size must match the input order (±1pt), else `OUTPUT_ORDER`.
9. **Delete temp files** after send or failure.

## Conventions

- Code comments, staff-facing messages, and test names are in **Indonesian**. This file is in English.
- Every new feature needs tests for: success, rejected input, engine failure, and the audit row it writes.
- Tests use fake engines and a fake Stirling, never the real one. To check page order, build PDFs whose pages have
  **different widths** and compare the widths.
- Never commit `.env`, `data/`, `uji/`, `*.pdf`. Line endings are LF.

## Gotchas

- `pytest` only works from `api/` (`pythonpath = ["."]` in `pyproject.toml`).
- `db/init/schema.sql.in` runs only when the Postgres volume is empty. The `.in` extension is intentional.
- Docker published ports bypass `ufw`; restrict with the `DOCKER-USER` chain, the shared secret, and a bind to the VM IP.
- `GATEWAY_SECRET` must be ≥24 chars and not start with "change"; `ADMIN_USERS` is required (`DOMAIN\user`, comma-separated).

## Not yet verified (delete a line when it is verified)

- **Real Stirling.** Assumed: `POST /api/v1/general/merge-pdfs`, field `fileInput` repeated per file,
  `sortType=orderProvided` keeps order, `GET /api/v1/info/status` for health. Test on the VM with PDFs of different
  page widths and reversed file names.
- **IIS/ARR setup** (`HTTP_X_REMOTE_USER` server variable, `X-Gateway-Secret`, `X-Forwarded-For`, upload limit, timeouts).
- Deleting the **last** audit row is invisible to the chain; an admin must save `head_hash` elsewhere regularly.