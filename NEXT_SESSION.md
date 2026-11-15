# Next session: start here

Handoff written 2026-11-14 at the end of a long session. Read this, then `CLAUDE.md` (project rules), then work.
Delete or rewrite this file once its first steps are done.

## 1. First steps (in order)

1. **Push.** Nothing from this work is on GitHub yet: the old session had no GitHub credentials.
   - Local `main` is 1 commit ahead of `origin/main` (`a569861`, steps 1-2 of the roadmap).
   - Local `gui` holds everything since (10 commits, latest `b2761c8`).
   - With the new GitHub connector, or from the owner's machine: `git push -u origin main gui`.
   - A second clone exists at `/home/inspector/dev/entra_azure_auditor` (made while trying to push). It only holds
     copies of these branches. Delete it once the push succeeded, unless the session uses it as its checkout.
2. **Check the Microsoft documentation skill/tool is loaded** and use it for every Graph endpoint, permission and
   property from now on (owner's request). Last session used WebFetch on learn.microsoft.com instead; the pages used are
   listed in section 6.
3. **Set up and run the checks** (the environment's `python` is missing; use `python3` and a venv):
   ```bash
   python3 -m venv .venv && .venv/bin/python -m pip install -r requirements-dev.txt   # includes PySide6 + pytest-qt
   .venv/bin/python -m pytest          # 759 passed at handoff (GUI tests run headless, QT_QPA_PLATFORM=offscreen)
   .venv/bin/ruff check .              # clean at handoff
   ```
4. **Fix the scope bug (section 4)** before new features. Then pick from the ideas (section 5), and ask the owner
   about role-assignment writes (section 3) when that comes up.

## 2. What exists now

Branch `gui`, on top of roadmap steps 1-2 (green under real deps, `toolkit/flow.py` change flow, CI workflow).

**Desktop app** (`auditor gui`, PySide6 as optional extra `.[gui]`):
- Sign-in dialog: tenants from `~/.entra_auditor/tenants.json` (fallback: the `.env` tenant), one token cache per
  tenant, device code (copy/open/cancel) or browser (5-minute timeout). User sign-in only.
- Main window = navigation | page stack. Ready pages: **Users**, **Administrative units**, **Roles / PIM**.
  Groups, Audit, Action log are shown greyed out.
- Users: whole directory loaded once in the background (`$select`, `$top=999`), type-to-filter locally (50k users
  filter in ~0.3 s); tabs General, Groups, Sign-in methods, Certificate IDs, Roles (one profile load feeds all);
  enable/disable.
- Administrative units: flat AU list (AUs don't nest) with dynamic/restricted badges | members (users, groups,
  devices) | Properties + scoped Roles (active and PIM-eligible). Add users/groups/devices via pickers, remove,
  edit settings (name, description, dynamic membership rule). Double-click a user to open it on the Users page.
- Roles / PIM: your directory roles and **PIM for Groups** assignments; activate (duration + justification),
  deactivate.
- Every change: preview (shows the exact requests; Cancel is the default; bodies wrap, never elide) -> confirm ->
  on "forbidden": choose a PIM role **or a PIM group whose membership carries the role** -> justification ->
  wait, refresh token, retry -> result.

**Toolkit additions** (UI-neutral, tested without Qt): `tenants.py`, `toolkit/directory.py` (load users, groups,
devices), `toolkit/group_pim.py`, `toolkit/admin_units.py`, AU plans in `toolkit/actions.py`
(`plan_add_au_members`, `plan_remove_au_members`, `plan_update_admin_unit`), auth hooks (device-code callback,
cancel, browser timeout).

**Tests:** `tests/test_gui_*.py` (pytest-qt, skip without PySide6), `test_flow.py`, `test_group_pim.py`,
`test_admin_units.py`, `test_tenants.py`, `test_directory.py`; real-client request tests in
`test_real_client_flows.py` for every new write. `FakeTenant` has opt-in PIM for Groups (`add_pim_group`),
administrative units (`add_admin_unit`) and devices, all enforcing Entra's rules.

## 3. Open decisions for the owner

- **Role assignment writes** (assigning admin roles, tenant-wide or AU-scoped). Options offered: (1) stay
  read-only for now [recommended until PIM is tested live], (2) PIM-eligible assignments only, (3) eligible and
  permanent active. Writes would need Privileged Role Administrator and `RoleManagement.ReadWrite.Directory`.
- **Licence** for the repo: `LICENSE` was deleted on purpose; don't add one until the owner chooses.
- Owner's biggest tenant size was never given (assumed under 50k users).

## 4. Known bug to fix first: PIM role scope is ignored

Found by reading the code, not yet reproduced in a test. `PimService.match()` (`toolkit/pim.py`) matches eligible
roles by **name only**, and `eligible()` can return the same role twice (tenant-wide `/` and scoped to
`/administrativeUnits/<id>`). The elevation flow could therefore offer an AU-scoped role for a target outside that
AU: activation succeeds, the retry is still denied.

Fix: prefer tenant-wide eligibility; offer an AU-scoped role only when the plan's target is a member of that AU
(look up `GET /users/{id}/memberOf/microsoft.graph.administrativeUnit`, or the group/device equivalent; check the
docs). Write the failing test first (FakeTenant: eligible for "User Administrator" scoped to an AU the target isn't
in). Same question for `GroupPimService.granting()` if a group's role assignment is AU-scoped.

## 5. Ideas the owner liked the sound of (pick with the owner)

1. "Who can manage this user?" tab: tenant-wide admins + AU-scoped admins via the user's AUs + restricted-AU
   shielding (Entra's version of ADUC delegation).
2. Leaver workflow: one preview for disable, revoke sessions, reset password, remove from groups/AUs/licences;
   clear partial-success report (roadmap item 4).
3. Undo from the action log: build the reverse plan from logged before/after values, through the same preview.
4. PIM timer in the status bar ("User Administrator, 42 min left"), warning before expiry.
5. "No MFA registered" filter in the user list from the authentication-methods registration report (one bulk call;
   check endpoint, licence and permission in the docs).
6. Devices page, then BitLocker recovery keys and Windows LAPS (show once, never log, like passwords).
7. Bulk changes from CSV with a full preview.
8. Read-only mode for junior helpdesk staff (hide every write).
9. Dynamic-rule preview before applying (the test API may be beta-only: check).
Also still on the roadmap: Groups page, Audit page, Action log page, tenant switcher, packaging.

## 6. Not verified against a live tenant

Everything below was built from the Graph v1.0 docs and tested only against fakes. Test these in a real tenant
first; the owner's test tenant has no eligible roles, so PIM will be tested in a production tenant later.
- PIM activation (roles), and the GUI elevation dialogs.
- PIM for Groups (service, Roles / PIM page, group candidates in the elevation flow).
- Administrative units: reads, member add/remove, settings update. Specifically whether
  `$filter=directoryScopeId eq '/administrativeUnits/<id>'` works on `roleAssignments` /
  `roleEligibilitySchedules` (fallback: `scopedRoleMembers`, active only).
- GUI sign-in (device code and browser) and the directory load at scale.
- The assumption that permissions consented on the app registration but **not requested at sign-in** still
  appear in the token. New permissions (PIM for Groups, `AdministrativeUnit.ReadWrite.All`, `Member.Read.Hidden`)
  are deliberately not in `TOOLKIT_SCOPES`, because requesting an unconsented scope breaks every sign-in.
- Plus the older list in CLAUDE.md (group add/remove after 0.2.3, certificate-ID writes, `$expand` at scale).

Docs pages used last session (re-check with the docs skill):
- privilegedAccessGroup: create assignmentScheduleRequest; eligibilityScheduleInstance filterByCurrentUser
- administrativeUnit resource; add member; list members; list scopedRoleMembers
- List unifiedRoleAssignments (`$expand=principal` documented; `directoryScopeId` filter not explicitly listed)
- List devices (`Device.Read.All` or `Directory.Read.All`; AU links use the object `id`, not `deviceId`)

## 7. Working notes

- Screenshots for checking layouts: drive the real widgets against `FakeTenant` with
  `QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=2` and `widget.grab().save(...)`. This caught real bugs (Enter applied
  a change; the preview cut off request bodies). Look at every new screen this way.
- Qt rules learned: worker results go through `gui/tasks.py TaskRunner` (never update widgets from a worker);
  network calls (including token refresh) never on the UI thread; use `dialog.open()` + `finished`, not `exec()`,
  so tests and workers keep running; `QMessageBox` statics are monkeypatched in tests.
- Commits so far end with the attribution line from the session's instructions; keep model names out of commits.
