# Entra Security Auditor

A **read-only** command line tool that audits a Microsoft Entra ID (Azure AD) tenant through the
Microsoft Graph API and explains what it finds.

It checks for:

- **Inactive accounts**: members, guests, never-signed-in accounts, stale guest invitations
- **Privileged accounts**: Global Admin count, admins without MFA or with only weak methods, permanent
  (non-PIM) assignments, guests/apps holding roles, inactive or synced admins
- **MFA and Conditional Access**: registration gaps, missing baseline policies (MFA for all users and
  admins, legacy-auth block, ...), and a **plain-English breakdown of every CA policy** (who it covers,
  who is excluded, what it applies to, what it does)
- **Stale or risky apps**: expired/expiring credentials, inactive service principals, abandoned apps,
  apps with powerful Graph permissions

Results are printed in the terminal and can be exported as JSON or CSV.

> The tool only needs **read** permissions and never changes your tenant.

---

## Quick start

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt    # or: pip install -e .   (adds the `auditor` command)

cp .env.example .env               # then edit it (see "Connect it to your tenant")
python -m entra_auditor permissions   # check your app has the access it needs
python -m entra_auditor run           # run an audit
python -m entra_auditor menu          # or use the interactive menu
```

After `pip install -e .` you can type `auditor ...` instead of `python -m entra_auditor ...`.

## Connect it to your tenant

Register an app in **Entra admin center -> App registrations -> New registration** (single tenant).
Note the **Application (client) ID** and **Directory (tenant) ID** and put them in `.env`.

Choose how the tool signs in:

### Option A: app registration (unattended; best for scheduled runs)

1. **Certificates & secrets**: add a client secret, or (better) upload a certificate.
2. **API permissions -> Add -> Microsoft Graph -> Application permissions**, add the permissions in the
   table below, then click **Grant admin consent**.
3. In `.env`: `AUDITOR_AUTH_MODE=app` plus `AZURE_CLIENT_SECRET` (or the certificate variables).

### Option B: sign in as yourself (interactive)

1. **Authentication -> Add a platform -> Mobile and desktop applications**, add the redirect URI
   `http://localhost` (browser mode), and set **Allow public client flows = Yes** (device-code mode).
2. **API permissions -> Add -> Microsoft Graph -> Delegated permissions**: the same names as below, then
   grant admin consent.
3. In `.env`: `AUDITOR_AUTH_MODE=device` (or `browser`). Leave the secret empty.
4. Run `auditor login`. Sign in with an account that has **Global Reader** (read-only is enough; a
   Global Admin is more access than an audit needs).

In user mode your access is the app's permissions **intersected with your own roles**, so a normal user
will see "data unavailable" for things like Conditional Access.

### Permissions

| Permission | Used for |
|---|---|
| `User.Read.All` | users |
| `AuditLog.Read.All` | sign-in activity (inactive accounts, apps) |
| `Reports.Read.All` | MFA registration report |
| `RoleManagement.Read.Directory` | directory role assignments |
| `RoleEligibilitySchedule.Read.Directory` | PIM eligible roles |
| `RoleAssignmentSchedule.Read.Directory` | permanent vs time-bound assignments |
| `Policy.Read.All` | Conditional Access, security defaults |
| `Application.Read.All` | app registrations, service principals |
| `Group.Read.All` | names/sizes of groups used in CA exclusions and role groups |

Some data needs **Entra ID P1/P2** (sign-in activity, Conditional Access, PIM). Without it the tool tells
you which checks were skipped instead of failing. `auditor permissions` shows what your token has.

## Commands

| Command | What it does |
|---|---|
| `auditor run` | Run an audit. `--checks inactive,privileged,mfa_ca,stale_apps`, `--out ./reports`, `--fail-on high` |
| `auditor findings [RUN]` | Browse findings: `--min-severity high`, `--check ADMIN`, `--search bob`, `--detail` |
| `auditor policies [RUN]` | Conditional Access overview; `--name "MFA"` gives the full plain-English breakdown |
| `auditor compare [OLD] [NEW]` | New, resolved and changed findings between two runs |
| `auditor runs` / `export` | List saved runs / write JSON and CSV reports |
| `auditor permissions` | Needed vs granted Graph permissions |
| `auditor login` / `logout` / `whoami` | Manage the user sign-in (user modes) |
| `auditor menu` | Arrow-key menu over all of the above |

`RUN` is `latest` (default), `previous`, a run-id prefix, or a `.json` file. Runs are saved to
`~/.entra_auditor/runs` (override with `AUDITOR_RUNS_DIR`).

**Exit codes:** `0` ok, `1` the audit could not run, `2` findings at or above `--fail-on` exist, which
makes it easy to gate a pipeline:

```bash
auditor run --checks mfa_ca,privileged --fail-on high --out reports
```

Thresholds (inactivity days, max Global Admins, ...) live in `AuditConfig`
(`entra_auditor/checks/_common.py`); the common ones are CLI flags (`--inactive-days`, `--guest-days`,
`--admin-days`).

## Security notes

- **Never commit secrets.** `.env`, certificates, token caches and audit output are in `.gitignore`.
  If a secret ever lands in git history, rotate it. Deleting the file is not enough.
- **Reports are sensitive.** They map your tenant's weaknesses. Files are created owner-only (`0600`);
  keep them out of public places, tickets, and chat.
- In user modes, the token cache (`~/.entra_auditor/token_cache.json`) contains refresh tokens. Treat it
  like a password and use `auditor logout` when finished.
- Prefer a **certificate** over a client secret, and keep the app registration read-only.
- CSV exports neutralise spreadsheet formulas (cells beginning `=`, `+`, `-`, `@` get a leading `'`).

## Project layout

```
entra_auditor/
├── auth.py             # MSAL: app registration or user sign-in
├── graph/client.py     # httpx wrapper: paging, retry on 429/503, $select
├── graph/collectors.py # users, roles, MFA, CA policies, apps, service principals
├── models.py           # Pydantic models, incl. Finding
├── checks/             # inactive_users, privileged, mfa_ca (+ ca_analysis), stale_apps
├── engine.py           # runs selected checks, produces an AuditRun, diffs runs
├── reports.py          # JSON / CSV writers and the local run store
└── cli.py              # Typer + Rich, interactive menu
```

**Roadmap:** PostgreSQL storage (SQLAlchemy + Alembic), a FastAPI REST layer, automated tests and CI,
Docker Compose.

## Development

```bash
pip install -r requirements-dev.txt
ruff check . && mypy entra_auditor && pytest
```

Checks are pure functions of a `TenantSnapshot`, so they can be unit-tested without Graph or a database
(`respx` is included for testing the Graph client).
