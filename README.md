# Entra Security Auditor

A command line tool that **audits** a Microsoft Entra ID (Azure AD) tenant through the
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

- **Unowned, empty and stale groups**: owners and users confirmed per group; mail-enabled security groups
  and distribution lists are skipped (they are managed in Exchange); "stale" also requires that nothing
  visibly uses the group (app assignments, nesting, directory roles, licences, Teams, Conditional Access)

It also includes an **identity toolkit** (`auditor id | group | pim | toolkit`) to look up identities and make
changes, with just-in-time elevation through PIM.

> **The audit is read-only** (it never changes your tenant and needs only read permissions).
> **The toolkit writes**, so it uses a separate, explicit set of permissions, previews every change,
> asks before applying it, and records it in a local log. See [Identity toolkit](#identity-toolkit).

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

Note the `-m`: `python entra_auditor ...` (a path) fails with "attempted relative import", and `entra_auditor ...` isn't a command (the installed command is `auditor`). Help is `--help`, not `help`.

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
| `Group.Read.All` | names/sizes of groups used in CA exclusions and role groups, group audit |
| `Directory.Read.All` | group audit usage signals (app assignments, nesting, directory roles) |

Some data needs **Entra ID P1/P2** (sign-in activity, Conditional Access, PIM). Without it the tool tells
you which checks were skipped instead of failing. `auditor permissions` shows what your token has.

## Commands

| Command | What it does |
|---|---|
| `auditor run` | Run an audit. `--checks inactive,privileged,mfa_ca,stale_apps`, `--out ./reports`, `--fail-on high` |
| `auditor findings [RUN]` | Browse findings: `--min-severity high`, `--check ADMIN`, `--search bob`, `--detail` |
| `auditor policies [RUN]` | Conditional Access overview; `--name "MFA"` gives the full plain-English breakdown |
| `auditor ca-report [RUN]` | Self-contained **HTML report** of your Conditional Access policies (policy map, gaps, searchable cards). `--open`, `--mermaid` |
| `auditor compare [OLD] [NEW]` | New, resolved and changed findings between two runs |
| `auditor runs` / `export` | List saved runs / write JSON and CSV reports |
| `auditor permissions` | Needed vs granted Graph permissions |
| `auditor id ...`, `group ...`, `pim ...`, `toolkit` | Identity toolkit (see below) |
| `auditor login` / `logout` / `whoami` | Manage the user sign-in (user modes) |
| `auditor menu` | Arrow-key menu over all of the above |

`RUN` is `latest` (default), `previous`, a run-id prefix, or a `.json` file. Runs are saved to
`~/.entra_auditor/runs` (override with `AUDITOR_RUNS_DIR`).

**Exit codes:** `0` ok, `1` the audit could not run, `2` findings at or above `--fail-on` exist, which
makes it easy to gate a pipeline:

```bash
auditor run --checks mfa_ca,privileged --fail-on high --out reports
```

**Conditional Access report.** `auditor ca-report --open` writes one offline HTML page: an overview, the
baseline gaps, a who -> policy -> outcome map of every policy, and searchable cards that explain each policy
in plain English (who, exclusions with group sizes, apps, conditions, action, concerns and fixes). Add
`--mermaid` for a Markdown file with the same diagram as Mermaid source (GitHub renders it), or use
`--formats json,csv,html,mermaid` with `auditor run`/`export`. The HTML loads nothing from the network.

Thresholds (inactivity days, max Global Admins, ...) live in `AuditConfig`
(`entra_auditor/checks/_common.py`); the common ones are CLI flags (`--inactive-days`, `--guest-days`,
`--admin-days`).

## Identity toolkit

Look people up, fix things, and elevate only when needed. It is meant for **user sign-in**
(`--mode device` or `browser`; the toolkit defaults to device code if your environment is set to `app`),
so you can sign in holding **no admin role** and activate one through PIM only for the task.

```bash
auditor id search bob@contoso.com          # by UPN, email or alias address, name, employee id, alias, object id
auditor id show bob@contoso.com            # attributes, sign-in, groups, roles, auth methods, certificate IDs
auditor id edit bob --set title="Staff Engineer" --set dept=IT
auditor id password bob                    # Entra generates it; shown once, never logged (--prompt / --local)
auditor id cert-add bob --type ski AB:CD:EF # prefix X509:<SKI> pre-filled; you paste only the data
auditor id disable bob  /  enable  /  revoke
auditor group add-member "Finance Share" bob alice
auditor group add-owner  "Project X" bob   # the usual fix for an unowned group
auditor group stale --only unowned --export unowned-groups.csv    # from the latest audit
auditor pim list | activate "User Administrator" --reason INC-123 --minutes 60 | deactivate ...
auditor toolkit                            # interactive menu over all of this
```

**How a change works.** Every change is *planned* first (exactly which Graph requests would be sent, with
secrets redacted), shown to you, and applied only after you confirm. `--dry-run` shows the plan and sends
nothing; `--yes` skips only the confirmation, never the preview. If Entra answers "forbidden", the tool
offers to activate a suitable eligible PIM role (it picks from the roles that can do that task), waits for it
to take effect, refreshes your token and retries. Use `--elevate` / `--no-elevate` / `--reason` to script that.
Everything applied is appended to `~/.entra_auditor/actions.jsonl` (who, what, to whom, result; never a
password). `auditor id log` shows recent entries.

**Guards.** The tool refuses, with the reason, changes Graph can't make: groups synced from on-premises AD,
dynamic-membership groups (membership), and Exchange-managed groups (mail-enabled security, distribution).
Adding someone already in a group, or removing someone who isn't, is treated as already done.

**Certificate user IDs** (certificate-based authentication). Prefixes are case-sensitive:
`X509:<PN>`, `<RFC822>`, `<SKI>`, `<SHA1-PUKEY>`, `<I>..<SR>..`, `<I>..<S>..`, `<S>..`. The tool adds the prefix;
hex values pasted with colons or spaces are tidied. Cloud-only users need at least Privileged Authentication
Administrator; synced users Hybrid Identity Administrator.

**Setup for the toolkit** (in addition to the audit setup): on the app registration add these **delegated**
permissions with admin consent, and enable *Allow public client flows*:

| Permission | Used for |
|---|---|
| `User.ReadWrite.All` | edit users, enable/disable |
| `Group.ReadWrite.All` | add/remove group owners (membership alone would need less) |
| `Directory.Read.All` | read users, groups, memberships |
| `UserAuthenticationMethod.ReadWrite.All` | password reset, auth methods |
| `User.RevokeSessions.All` | revoke sessions |
| `RoleManagement.Read.Directory`, `AuditLog.Read.All` | show roles and last sign-in |
| `RoleEligibilitySchedule.Read.Directory`, `RoleAssignmentSchedule.ReadWrite.Directory` | see and activate **your own** PIM roles |

These grant the *app* the ability to act, but what a given sign-in can actually do is still limited by the
roles the signed-in person holds (that is why elevation matters). Set `AUDITOR_TOOLKIT_SCOPES` to drop
capabilities you don't want (for example remove `UserAuthenticationMethod.ReadWrite.All` if you never reset
passwords).

## Desktop app (preview)

A Qt window for the identity toolkit: users on the left, their properties on the right, and every change
shown as a preview you confirm (with PIM elevation when Entra says you need a role).

```bash
python -m pip install ".[gui]"     # PySide6 is optional: the CLI doesn't need it
python -m entra_auditor gui
```

It signs in as you (device code or browser), never with an app secret, so the app registration needs
**delegated** permissions only (the toolkit table above); application permissions are used solely by the
unattended audit (`AUDITOR_AUTH_MODE=app`). Tenants come from
`~/.entra_auditor/tenants.json`, or from `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` in `.env` when that file is missing:

```json
{"tenants": [
  {"name": "Contoso", "tenant_id": "<tenant id>", "client_id": "<app id>"},
  {"name": "Fabrikam", "tenant_id": "fabrikam.onmicrosoft.com", "client_id": "<app id>"}
]}
```

Large tenants: the user list stays responsive with several hundred thousand user objects, and a box next to
the filter chooses what is loaded (all users, members, guests, or only users synced from on-premises AD) as a
server-side filter. Add `"user_scope": "members"` (or `guests`, `synced`) to a tenant in `tenants.json` to start
with that scope.

Each tenant keeps its own token cache (`~/.entra_auditor/tenants/<tenant id>.token_cache.json`). The app
registration needs **Allow public client flows** for device code, and the `http://localhost` redirect URI
(Mobile and desktop platform) for browser sign-in.

So far:
- **Users:** whole directory loaded once and filtered as you type; General, Groups, Sign-in methods,
  Certificate IDs and Roles tabs; enable/disable.
- **New user...** (toolbar, Users page): create a user, modelled on the selected user if there is one:
  department, title, company, office and usage location, the manager, direct licences that still have a free
  unit, and group memberships Graph can change. The initial password is generated, never shown in previews
  or logs, and shown once at the end. Admin roles, role-assignable groups and administrative units are
  never copied.
- **Offboard...** (toolbar, Users page): the leaver workflow as one previewed change: disable, sign out
  everywhere, reset the password, remove direct licences, group memberships, optionally ownerships, and
  administrative units. It lists what it leaves alone (admin roles, dynamic/synced/Exchange groups, the
  mailbox), keeps going when a step is refused, and reports step by step what was and wasn't done.
- **Licences** (a tab on each user): what they hold and whether each licence is direct or inherited from a
  group; assign and remove direct licences from a tick list showing what is free, setting the usage location
  in the same change when it is missing.
- **Who can manage** (a tab on each user, read-only): the admins whose role reaches this user and what each
  can do (reset password, enable/disable, sign-in methods, edit profile, licences), tenant-wide or through an
  administrative unit, active or PIM-eligible. It applies Microsoft's rules: a restricted management unit
  shields the user from tenant-wide admins, and a user's own admin roles limit who may reset their password.
  Built-in roles only; you need a role that can read role assignments (for example Global Reader).
- **Groups:** every group loaded once and filtered as you type (Exchange-managed groups hidden unless asked
  for); members, owners, properties and what the group belongs to; add/remove users, nested security groups
  and owners. Synced, dynamic and Exchange-managed groups explain why they are read-only. Double-click moves
  between users and groups.
- **Administrative units:** units on the left, members in the middle, settings and scoped roles on the right
  (like OUs in ADUC, but AUs don't nest); add/remove users, groups and devices, edit name, description and
  dynamic membership.
- **Roles / PIM:** your directory roles and PIM for Groups assignments, with activate/deactivate. When a
  change is denied, the app also offers PIM groups whose membership carries the needed role.

Optional permissions for the app registration (with admin consent): `PrivilegedEligibilitySchedule.Read.AzureADGroup`
and `PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup` for PIM for Groups; `AdministrativeUnit.ReadWrite.All`
to change administrative units (plus `Member.Read.Hidden` to list hidden-membership units). They aren't requested
at sign-in, so a missing one only affects that page.

## Security notes

- **Never commit secrets.** `.env`, certificates, token caches and audit output are in `.gitignore`.
  If a secret ever lands in git history, rotate it. Deleting the file is not enough.
- **Reports are sensitive.** They map your tenant's weaknesses. Files are created owner-only (`0600`);
  keep them out of public places, tickets, and chat.
- In user modes, the token cache (`~/.entra_auditor/token_cache.json`) contains refresh tokens. Treat it
  like a password and use `auditor logout` when finished.
- Prefer a **certificate** over a client secret. For audits keep the app registration read-only; use the toolkit
  with a **user sign-in**, not the app's own permissions (`--mode app` works but has no PIM and no
  per-person accountability, and the tool warns you).
- Passwords generated or reset by the toolkit are shown once and never written to disk or the action log.
- CSV exports neutralise spreadsheet formulas (cells beginning `=`, `+`, `-`, `@` get a leading `'`).

## Project layout

```
entra_auditor/
├── auth.py             # MSAL: app registration or user sign-in
├── graph/client.py     # httpx wrapper: paging, retry on 429/503, $select
├── graph/collectors.py # users, roles, MFA, CA policies, apps, service principals
├── models.py           # Pydantic models, incl. Finding
├── checks/             # inactive_users, privileged, mfa_ca (+ ca_analysis), stale_apps, stale_groups
├── ca_report.py        # Conditional Access HTML report and Mermaid diagram
├── cli_common.py       # helpers shared by the audit CLI and the toolkit CLI
├── toolkit/            # identity toolkit: search, profile, actions (plan/execute), pim, ui, cli
├── engine.py           # runs selected checks, produces an AuditRun, diffs runs
├── reports.py          # JSON / CSV writers and the local run store
└── cli.py              # Typer + Rich, interactive menu
```

**Roadmap:** PostgreSQL storage (SQLAlchemy + Alembic), a FastAPI REST layer, automated tests and CI,
Docker Compose.

## Development and tests

```bash
pip install -r requirements-dev.txt
python -m pytest                      # the whole suite, a few seconds
python -m pytest -k pim               # only tests whose name contains "pim"
python -m pytest --cov=entra_auditor  # with coverage
ruff check .
```

Use `python -m pytest` rather than a bare `pytest`: it always runs under the Python of your active virtualenv. A bare
`pytest` can resolve to a different installation (system-wide or `~/.local/bin`) that can't see the project's
packages, which shows up as `ModuleNotFoundError: No module named 'questionary'` (or `typer`, `rich`, ...).

The suite never contacts Microsoft and needs no credentials. Graph is replaced by in-memory fakes
(`tests/fakes.py`): `FakeTenant` is a small tenant that enforces permissions the way Entra does (writes are
denied until a PIM role is activated, and a newly activated role can take a moment to take effect), and
`FakeGraph` serves canned responses. An autouse fixture clears every `AZURE_*`/`AUDITOR_*` variable and points the
run store, token cache and action log at a temporary directory, so tests can't touch your real settings or your
home directory.

| Tests | Cover |
|---|---|
| `test_odata`, `test_certids`, `test_passwords`, `test_audit_log` | query escaping (injection), certificate-ID formats, password rules, secrets never logged |
| `test_client`, `test_auth` | paging, retry rules (a POST is never resent after an ambiguous failure), token flows |
| `test_collectors`, `test_stale_groups` | Graph JSON parsing and how collection degrades when one source fails |
| `test_checks_*`, `test_ca_analysis` | every check's thresholds, severities and edge cases ("exactly 90 days is not inactive") |
| `test_engine`, `test_reports`, `test_ca_report` | run orchestration, CSV/JSON/HTML output, formula and markup injection |
| `test_search`, `test_profile`, `test_actions`, `test_pim` | the identity toolkit: plans, guards, execution, elevation |
| `test_toolkit_cli`, `test_toolkit_menu`, `test_cli_wiring` | the commands and menus, including the real Typer parsing |

**Adding a check?** Build the smallest snapshot with `tests/builders.py`, call the check, and assert on the
finding's `check_id` and `severity`. Test the boundary on both sides.

**CI** (`.github/workflows/ci.yml`) runs the suite on Python 3.10 to 3.13, a command-line smoke test, and
ruff/mypy (advisory until you've had a clean run: delete `continue-on-error` from the ruff step to make it
block). It has read-only permissions and no secrets. Dependabot keeps dependencies and actions current.
For a stricter supply chain, pin the actions in `ci.yml` to full commit SHAs.

<!-- Once the repo is on GitHub, add a status badge under the title:
[![CI](https://github.com/<you>/<repo>/actions/workflows/ci.yml/badge.svg)](https://github.com/<you>/<repo>/actions/workflows/ci.yml) -->
