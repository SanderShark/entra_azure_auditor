# Next session: start here

Handoff written 2026-11-14 at the end of a long session; updated the same day by the next session (scope fix). Read this, then `CLAUDE.md` (project rules), then work.
Delete or rewrite this file once its first steps are done.

## 1. First steps (in order)

1. **Push.** Still nothing from this work on GitHub. Two sessions in a row had no GitHub credentials
   (`git push` cannot authenticate; attaching the repository to the cloud session was not permitted).
   - Local `main` is 1 commit ahead of `origin/main` (`a569861`, steps 1-2 of the roadmap).
   - Local `gui` holds everything since.
   - From the owner's machine, or a session with GitHub access: `git push -u origin main gui`.
   - A second clone exists at `/home/inspector/dev/entra_azure_auditor` (made while trying to push). It only holds
     older copies of these branches. Delete it once the push succeeded.
2. **Microsoft documentation:** no docs skill was loaded in the second session either; WebFetch on
   learn.microsoft.com was used (pages in section 6). Use the skill if it is there.
3. **Set up and run the checks** (the environment's `python` is missing; use `python3` and a venv):
   ```bash
   python3 -m venv .venv && .venv/bin/python -m pip install -r requirements-dev.txt   # includes PySide6 + pytest-qt
   QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest     # 894 passed
   .venv/bin/ruff check .                                   # clean
   ```
4. The scope bug (section 4) is **fixed**, and idea 1 ("Who can manage this user?") is **built**. Next: pick from the ideas (section 5) with the owner, and ask about
   role-assignment writes (section 3) when that comes up.

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
- Tenant size (answered 2026-11-15): ~30k users but 300k+ user objects (guests, cross-tenant sync). The list model
  was rewritten for that and a load scope added (all / members / guests / synced; `user_scope` in tenants.json).
  Still open: which scope really is "their 30k" (cross-tenant-synced users may be userType Member), memory at 300k
  (~650 MB; slimmer row objects would fix it), and the same treatment for the Groups page and the pickers.
- **Entra Connect sync-scoping rules** (owner's idea, low priority, sysadmin-only): they keep objects out of sync by a
  designated OU and by `extensionAttribute14 = "no0365sync"`; other tenants differ. Wanted: import the rules into
  the tool, maybe a rule builder. Constraints: Connect Sync rules live on the Connect server, not in Graph, so the
  tool needs an export (the Connect configuration export JSON, or `Get-ADSyncRule` output); Cloud Sync scoping IS
  in Graph (synchronization jobs). Questions to ask first: Connect Sync or Cloud Sync? What should the tool do with
  the rules: explain "why is/isn't this user synced", flag cloud objects that should have been filtered, or
  generate rules? Nothing built yet.

## 4. Fixed: PIM role scope was ignored

Roles were matched by name only. Reproduced in tests, then fixed (tests in `test_flow.py`, `test_pim.py`,
`test_group_pim.py`, `test_admin_units.py`, `test_real_client_flows.py`):
- A role eligible for one administrative unit is offered only when the plan's target (user or group) is a member
  of that unit; tenant-wide eligibility comes first and is no longer hidden by a scoped one of the same name.
- An active unit-scoped role that doesn't cover the target no longer counts as "you already have it", and waiting
  for an activation checks the scope.
- Same for PIM groups whose role assignment is unit-scoped (`GroupAccess.role_scopes`).
- A unit-scoped role is never offered for changing the unit itself (it manages the unit's members only).
- If the target's units can't be read, scoped roles are offered last with a caveat (unknown is not "no").
- The lookup is plain `GET /users|groups/{id}/memberOf` filtered by `@odata.type` (the OData cast needs
  ConsistencyLevel: eventual + $count), done only when a scoped role is in play.

Known gaps, not handled: a target in a **restricted management** unit can't be changed with a tenant-wide role
(the flow still offers it; the retry is denied); membership of **hidden-membership** units may be missing from
`memberOf` without Member.Read.Hidden; plans with several objects (group add/remove members) check the group
only, which is what Entra checks.

## 5. Ideas the owner liked the sound of (pick with the owner)

1. ~~"Who can manage this user?" tab~~ DONE (`toolkit/managers.py`, `ManagersTab` in `gui/user_detail.py`, loads
   when opened). Possible follow-ups: expand a group principal to its members; custom roles (read
   `rolePermissions`); admins reachable through PIM groups; the same tab for groups ("who can manage this
   group", incl. owners); a CLI command (`auditor id managers`); use the restricted-unit knowledge in the
   elevation flow (don't offer a tenant-wide role for a target in a restricted unit).
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
Groups page: DONE (`gui/groups_page.py`, `toolkit/groups.py`; members, owners, nested security groups, memberOf).
Not yet: create/delete a group, edit name/description/rule, "who can manage this group".
Also still on the roadmap: Audit page, Action log page, tenant switcher, packaging.

**EasyEntra comparison** (the owner wants to imitate it and do better; from easyentra.com, 2026-11-14). It is an
ADUC-style Windows console for on-prem AD + Entra: users, groups, licences, mailbox settings, MFA settings,
BitLocker, Windows LAPS, virtual user templates for onboarding, 20+ offboarding options, multi-tenant switching,
delegated calendar access, a PowerShell module. We don't do on-prem AD or Exchange. Gaps to close, in the order
suggested to the owner: ~~licences~~ (DONE: per-user tab, assign/remove; not yet: service-plan toggles, a tenant-wide
subscriptions page, group-based licensing) -> ~~leaver workflow~~ (DONE: `toolkit/leaver.py`, toolbar "Offboard..."; not yet: removing
admin roles, mailbox steps, a CLI command)
-> ~~onboarding from a template user~~ (DONE: `toolkit/onboarding.py`, toolbar "New user..."; not yet: saved templates
that aren't a live user, checking the UPN domain against verified domains, a CLI command) -> onboarding from a
template user -> Devices page with BitLocker keys and LAPS -> tenant switcher -> sign-in method management
(TAP, remove methods). Where we are already ahead: PIM just-in-time elevation, a preview of every change,
"who can manage", administrative units, the audit.

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
- Unit-scoped PIM roles in the elevation flow (`memberOf` listing units; `selfActivate` with a unit scope).
- Plus the older list in CLAUDE.md (group add/remove after 0.2.3, certificate-ID writes, `$expand` at scale).

Docs pages used last session (re-check with the docs skill):
- privilegedAccessGroup: create assignmentScheduleRequest; eligibilityScheduleInstance filterByCurrentUser
- administrativeUnit resource; add member; list members; list scopedRoleMembers
- List unifiedRoleAssignments (`$expand=principal` documented; `directoryScopeId` filter not explicitly listed)
- List a user's direct memberships / List group memberships (return administrative units; cast needs advanced query)
- Assign Microsoft Entra roles, "administrative unit scope" (scoped roles manage members, not the unit; role list)
- Privileged roles and permissions ("Who can reset passwords", "Who can perform sensitive actions" tables)
- Restricted management administrative units (who is blocked, what stays allowed)
- List unifiedRoleAssignments (example 1: `$filter=roleDefinitionId eq ..&$expand=principal`), List roleEligibilitySchedules
- Create user (required properties, 201 with the id, User.ReadWrite.All)
- user: assignLicense (body, permissions, roles)
- Add members (which object types a security / Microsoft 365 group can hold)
- List devices (`Device.Read.All` or `Directory.Read.All`; AU links use the object `id`, not `deviceId`)

## 7. Working notes

- Screenshots for checking layouts: drive the real widgets against `FakeTenant` with
  `QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=2` and `widget.grab().save(...)`. This caught real bugs (Enter applied
  a change; the preview cut off request bodies). Look at every new screen this way.
- Qt rules learned: worker results go through `gui/tasks.py TaskRunner` (never update widgets from a worker);
  network calls (including token refresh) never on the UI thread; use `dialog.open()` + `finished`, not `exec()`,
  so tests and workers keep running; `QMessageBox` statics are monkeypatched in tests.
- Commits so far end with the attribution line from the session's instructions; keep model names out of commits.
