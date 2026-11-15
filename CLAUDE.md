# entra-auditor: project notes for Claude Code

> **Starting a new session? Read `NEXT_SESSION.md` first** (handoff: push status, a known bug, open
> decisions, ideas). Remove this line when that file is retired.

Python tool for Microsoft Entra ID: a **read-only security audit** (checks, JSON/CSV/HTML reports) and an
**identity toolkit** that changes the tenant (users, passwords, certificate IDs, groups) with **PIM
just-in-time elevation**. Everything goes directly to Microsoft Graph; there is no server component.

Current version: see `entra_auditor/__init__.py` (0.2.3 at handoff). Next big goal: a **Qt desktop app**
in the spirit of EasyEntra (see Roadmap).

## Commands

```bash
python -m pip install -r requirements-dev.txt
python -m pytest                 # always `python -m pytest`; a bare `pytest` has picked the wrong Python before
python -m pytest -k pim          # subset
ruff check .
python -m entra_auditor --help   # note the -m; `python entra_auditor` is a path and fails
```

Configuration comes from `.env` (see `.env.example`). Never commit `.env`, certificates, token caches or
reports (`.gitignore` covers them).

## Layout

```
entra_auditor/
  auth.py              MSAL: app registration (client credentials) or user sign-in (device code / browser)
  graph/client.py      httpx Graph client: paging, retries, typed errors, writes, base_url
  graph/collectors.py  Graph JSON -> models; degrades per source on failure
  models.py            pydantic models incl. Finding, TenantSnapshot, DirectoryGroup
  checks/              pure check functions + ca_analysis (Conditional Access in plain English)
  engine.py            runs checks -> AuditRun; diffs runs
  reports.py           JSON/CSV writers, local run store (~/.entra_auditor/runs)
  ca_report.py         offline HTML report + Mermaid diagram for CA policies
  cli.py, cli_common.py   Typer/Rich audit CLI and interactive menu
  tenants.py           tenants.json (desktop app) + one token cache per tenant
  toolkit/             identity toolkit: search, profile, actions (plan/execute), pim, certids,
                       passwords, odata (escaping), audit_log, cli (commands + menu),
                       flow (the change flow as a UI-independent state machine),
                       ui (Rich rendering + `run_action`, the terminal driver for flow),
                       directory (load all users/groups once for local filtering),
                       group_pim (PIM for Groups), admin_units (AU reads; AU plans live in actions)
  gui/                 PySide6 desktop app (`auditor gui`, optional extra `.[gui]`): tasks (thread pool ->
                       UI thread), session, signin, user_model, user_detail, change (flow as dialogs),
                       pickers, admin_units_page, roles_page, main_window (nav | page stack), app
.github/workflows/ci.yml   ruff (blocking) + pytest on Python 3.10 and 3.13
tests/                 ~770 tests, no network; fakes.py, builders.py, conftest.py, gui_support.py;
                       test_gui_*.py use pytest-qt, run headless, and skip without PySide6
```

## Rules that must not be broken

1. **Changes only through the plan pipeline.** Build a plan (`toolkit/actions.py plan_*`, pure), then drive
   `toolkit/flow.py ChangeFlow` (confirm -> execute -> PIM elevation -> retry). UI code never calls
   `graph.post/patch/delete` or `execute_plan` directly. `--dry-run` sends nothing.
2. **Secrets.** A password is shown to the operator once and is never logged, saved or put in a plan's
   loggable form (`PlannedRequest.secret_keys`, `audit_log._scrub`). Tokens stay in-process.
3. **Unknown is not empty.** In `TenantSnapshot`, `None` = could not be collected, `[]` = collected and
   empty. Counts that can't be confirmed stay `None` and are never flagged.
4. **Checks are pure:** `(snapshot, now, cfg) -> list[Finding]`. No network, no `datetime.now()`.
5. **Retries:** a 429 is always retried; after a 5xx or network error a **POST is never resent** (it may
   have been applied). PATCH/DELETE/GET are retried.
6. **Escape all user input** placed in Graph queries/paths with `toolkit/odata.py` (`literal`, `segment`,
   `search_term`).
7. **One failing data source becomes a warning**, not a crashed audit. Only auth failures and exhausted
   retries abort collection.
8. **The group audit excludes mail-enabled security groups and distribution lists by default** (owner's
   requirement; they are managed in Exchange). Synced groups are never "unowned".
9. **PIM is for user sign-in only.** On "forbidden", offer an eligible role from the plan's
   `suggested_roles`, require a justification, wait for it to take effect, refresh the token, retry.
10. **Read-only audit scopes never include write permissions**; toolkit scopes are separate (`TOOLKIT_SCOPES`).

## Testing rules

- Every behaviour change gets a test at its boundary (both sides: "90 days is not inactive, 91 is").
- Fakes (`tests/fakes.py`) must never offer something the real `GraphClient` lacks.
  `tests/test_contract.py` enforces this. It exists because `graph.base_url` shipped missing while the fake had it.
- `tests/test_real_client_flows.py` drives writes through the **real** client on an httpx mock transport.
  Add one there for every new write.
- `tests/test_cli_wiring.py` uses the real Typer runner; keep it passing.
- Tests must not touch the network, real settings or the home directory (autouse `isolated_env` fixture).

## Lessons learned (bugs that already happened)

- `isPrivileged` isn't on v1.0 role definitions: a 400 on one optional source used to abort the whole audit.
- questionary `Choice(value=None)` silently becomes the title text: menus use string sentinels.
- Copying individual files over an older tree mixed versions twice: work in git.
- `GraphClient.base_url` was referenced but never defined: add-member/add-owner crashed live (fixed in 0.2.3).
- Newer Typer vendors click as `typer._click`, so `import click` fails: don't import click in tests.
- pytest's `capsys` re-installs its stream as `sys.stdout` each test phase; `fake_tty` patches
  `CaptureIO.isatty` rather than wrapping `sys.stdout`.
- `requires-python` is 3.10: no 3.12-only syntax (e.g. reusing the outer quote inside an f-string).
- Qt: a signal connected to a plain Python callable runs it in the EMITTING thread. Worker results go through
  `gui/tasks.py TaskRunner` (a relay to a QObject on the UI thread); never update widgets from a worker.
- New permissions (PIM for Groups, AdministrativeUnit.ReadWrite.All) are deliberately NOT added to
  TOOLKIT_SCOPES: requesting an unconsented scope breaks sign-in for every command. Pages explain a 403 instead.
- The change preview must show everything that will be sent: request bodies wrap, never elide (tested).
- Qt makes a dialog's first accept button the default on show: the change preview forced Cancel back as the
  default (Enter must never apply a change). Keep that test.

## What has and hasn't been verified against a live tenant

Verified live: app-mode audit run, `id search`, `pim list`, password reset (Entra returns the generated password).

**Not yet verified live:** PIM activation (the test tenant had no eligible roles) **including the desktop
app's elevation dialogs** (`gui/change.py`: role choice, justification, wait, retry; built and tested against
`FakeTenant` only, the owner will test in a production tenant), the desktop app's sign-in (device code and
browser through `gui/session.py`) and its directory load at scale, **PIM for Groups** (`toolkit/group_pim.py`,
the Roles / PIM page and group candidates in the elevation flow), **administrative units** (`toolkit/admin_units.py`,
the AU plans in `actions.py`, the AU page; in particular whether `$filter=directoryScopeId eq '/administrativeUnits/..'`
works on roleAssignments/roleEligibilitySchedules, which has a scopedRoleMembers fallback), and the assumption
that permissions consented on the app registration but not requested at sign-in (PIM for Groups, AU writes)
still appear in the token, group add/remove after the
0.2.3 fix, certificate-ID writes, the group audit's `$expand` behaviour at scale, and the `$expand` on the PIM
`filterByCurrentUser` listings. Treat these as the first things to test in a real tenant.

The test suite now runs green under the real libraries (checked 2026-11-14 on Python 3.13 with pytest 8.4,
pydantic 2.14, Typer 0.29, Rich 14.3, questionary 2.1, httpx 0.28, MSAL 1.39). Python 3.10 is covered by CI only.

## Roadmap

1. ~~Green under real dependencies~~ (done; ruff is blocking in `.github/workflows/ci.yml`).
2. ~~Extract the change flow~~ (done): `toolkit/flow.py ChangeFlow` returns `NeedsConfirmation(plan)`,
   `NeedsElevation(candidate_roles)`, `NeedsJustification(role)` or `Done(result, cancelled, activate_manually)`
   and is resumed with `confirm(bool)`, `choose_role(role|None)`, `justify(text|None)`. Messages and
   spinners go through a `Reporter` (`notice(Notice)`, `busy(text)`). The flow blocks while it executes and
   waits, so the GUI calls it from a worker. `ui.run_action` is the terminal driver; tests in `tests/test_flow.py`.
3. **Qt desktop app** (`entra_auditor/gui/`, PySide6, `auditor gui` command). Milestone 1 done on branch `gui`:
   sign-in dialog (tenants.json, device code with copy/open/cancel, browser with a 5-minute timeout), Users list
   (background load, type-to-filter), General tab, enable/disable through the flow dialogs. Since then: all user
   property tabs; Roles / PIM page (directory roles + PIM for Groups, activate/deactivate); Administrative
   units page (flat AU list | members | properties + scoped roles; add/remove users and groups, edit settings);
   group memberships offered as elevation candidates. Next: role assignment management (owner to decide on
   writes), Groups page, Audit, Action log, tenant switcher. Remaining design notes:
   - ADUC-style: navigation (Users, Groups, Roles/PIM, Audit, Action log) | list | property tabs
     (General, Groups, Sign-in methods, Certificate IDs, Roles, Activity).
   - Speed: load the directory once in the background (`$select`, `$top=999`, all pages), filter locally as
     you type; detail tabs load lazily; no 100-row paging.
   - Never block the UI thread: Graph calls run in workers (QThreadPool), results come back via signals.
   - Every change uses the step-2 flow as dialogs: preview -> confirm -> PIM elevation -> retry -> result.
   - Device-code / browser sign-in dialog; tenant switcher (one token cache per tenant).
   - Tests with pytest-qt, run headless in CI with `QT_QPA_PLATFORM=offscreen`.
4. **Later modules:** licences; BitLocker recovery keys and Windows LAPS (Graph; check endpoints and
   permissions in the docs); onboarding/offboarding templates; Exchange Online (needs more than Graph);
   packaging (PyInstaller or Briefcase) and code signing.

## If this becomes a commercial product

Decide the licence before the repo goes public (a permissive licence lets anyone resell it). Check
PySide6's LGPL obligations for distribution, Microsoft's trademark guidance before using "Entra" in a product
name, and plan a verified multi-tenant app registration for customers. Get legal advice for these.
