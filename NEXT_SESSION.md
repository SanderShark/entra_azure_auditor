# Next session: start here

Handoff, rewritten 2026-11-15. Read this, then `CLAUDE.md` (project rules and lessons), then work.
**Keep this file current** (the owner asked): update it in the same commit as each feature, and rewrite it when it
turns into a pile of patches.

## 1. First steps (in order)

1. **Check what is pushed.** `main` and `gui` were pushed by the owner on 2026-11-15 (`origin/gui` at `7738fb0`).
   Cloud sessions so far could fetch but NOT push (`git push` has no credentials; attaching the repository to the
   session was not permitted). So: `git fetch origin && git status -sb`, and tell the owner how many commits on `gui`
   are ahead of `origin/gui` when you finish, so they can push (`git push origin gui`).
   - A stale second clone exists at `/home/inspector/dev/entra_azure_auditor`; it can be deleted.
2. **Microsoft documentation.** No docs skill was loaded in any session so far; `WebFetch` on learn.microsoft.com was
   used (pages in section 7). Use the skill if it is there. Those fetches return the whole page: they are expensive.
3. **Set up and run the checks** (the environment has no `python`; use `python3` and a venv):
   ```bash
   python3 -m venv .venv && .venv/bin/python -m pip install -r requirements-dev.txt   # includes PySide6 + pytest-qt
   QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -o addopts=""    # 955 passed (the default addopts hide the summary)
   .venv/bin/ruff check .                                               # clean
   ```
4. Then: section 4 (what to build next) and section 3 (questions for the owner).

## 2. What exists now (branch `gui`)

**Desktop app** (`auditor gui`, PySide6 as optional extra `.[gui]`). Navigation | page. Every change goes through
preview (exact requests; Cancel is the default) -> confirm -> on "forbidden" a PIM role or PIM group -> justification
-> wait, refresh token, retry -> result.

| Page / feature | Where | Notes |
|---|---|---|
| Sign-in, **Switch tenant...** | `gui/signin.py`, `gui/app.py` (`session_loop`) | one token cache per tenant; user sign-in only |
| **Users** list | `gui/main_window.py`, `gui/user_model.py` | loaded once; instant filter/sort at 300k rows; load-scope box (all / members / guests / synced) and "Hide external (#EXT#)" |
| User tabs | `gui/user_detail.py` | General, Groups (double-click opens the group), **Licences** (lazy; assign/remove), Sign-in methods, Certificate IDs, Roles, **Who can manage** (lazy, read-only) |
| **New user...** | `gui/onboarding.py`, `toolkit/onboarding.py` | modelled on the selected user; password shown once |
| **Offboard...** | `gui/leaver.py`, `toolkit/leaver.py` | one multi-step plan; reports each step |
| Enable/disable | toolbar | |
| **Groups** | `gui/groups_page.py`, `toolkit/groups.py` | members, owners, nested security groups, memberOf; Exchange-managed hidden by default |
| **Devices** | `gui/devices_page.py`, `toolkit/devices.py` | BitLocker keys and LAPS passwords on request, shown once |
| **Administrative units** | `gui/admin_units_page.py`, `toolkit/admin_units.py` | members (users/groups/devices), settings, scoped roles |
| **Roles / PIM** | `gui/roles_page.py`, `toolkit/pim.py`, `toolkit/group_pim.py` | your roles and PIM-for-Groups; activate/deactivate |
| Audit, Action log | - | still greyed out in the navigation |

**Command line only:** the read-only audit; `auditor id|group|pim ...`; and **`auditor sync ...`** (section 5).

**Engine pieces worth knowing** (details in CLAUDE.md "Lessons learned"):
- `ActionPlan.continue_on_error`: multi-step plans report failed steps and carry on (offboarding, onboarding).
- `PlannedRequest.capture_id` + `actions.NEW_ID`: a plan can create an object and use its id in later steps, with
  retries while the new object replicates.
- PIM elevation respects role scope (`pim.scope_applies`): a role scoped to an administrative unit is only offered
  when the target is in that unit.
- `toolkit/managers.py`: Microsoft's "who can reset passwords / sensitive actions" tables and restricted-unit rules
  as data.

## 3. Open questions and decisions for the owner

- **Sync rules: a real export is needed** (see section 5). Ask for a redacted `Get-ADSyncServerConfiguration -Path`
  folder (or `Get-ADSyncRule | ConvertTo-Json -Depth 10`), and a `Get-ADUser` CSV with `distinguishedName` and
  `extensionAttribute14`.
- **Which load scope is "their 30k users"?** Tenant: ~30k users, 300k+ user objects (guests, cross-tenant sync).
  Default is still "all users"; `tenants.json` can set `user_scope` and `hide_external`. Hiding `#EXT#` is done while
  loading (Graph has no server-side `contains` on the UPN), so those pages are still downloaded. A server-side
  variant (`not endswith(userPrincipalName, '#EXT#@<initial domain>')` as an advanced query) is untested.
- **Role assignment writes** (assign admin roles, tenant-wide or unit-scoped): still undecided. Options: stay
  read-only [recommended until PIM is tested live], PIM-eligible only, or eligible and permanent. Offboarding
  therefore lists admin roles but does not remove them.
- **Licence** for the repo: `LICENSE` was deleted on purpose; don't add one until the owner chooses.
- Sync engine (answered): Entra Connect Sync primarily; a Cloud Sync connector also exists.

## 4. What to build next

Agreed order so far; items 1-5 of the EasyEntra list are done except the last:
1. **Sign-in method management** (Temporary Access Pass, removing methods): NOT STARTED. Check the docs per method
   type first (each type has its own delete endpoint; TAP is a POST on `temporaryAccessPassMethods`).
2. **Sync rules, next steps** (section 5): confirm the format against a real export; then a desktop page.
3. **Scale follow-ups:** the Groups and Devices pages and the pickers still use `QTableWidget`/`QListWidget` and will
   be slow with tens of thousands of rows (give them the `UserFilterProxy` treatment); 300k `UserSummary` objects cost
   ~650 MB (slimmer rows would fix it).
4. **Gaps left in finished features:** create/delete/edit a group; licence service-plan toggles and a tenant-wide
   subscriptions view; device enable/disable/delete and a user's devices on the user's tabs; "who can manage this
   group"; expand a group principal to its members in "Who can manage"; custom roles there; use the restricted-unit
   knowledge in the elevation flow (don't offer a tenant-wide role for a target in a restricted unit); CLI commands
   for offboarding/onboarding/licences.
5. **Still greyed out:** Audit page, Action log page. Then packaging (PyInstaller or Briefcase) and code signing.
6. **Ideas the owner liked earlier, not built:** undo from the action log (reverse plan from logged before/after
   values); PIM timer in the status bar; "no MFA registered" filter from the registration report; bulk changes from
   CSV with a full preview; read-only mode for junior helpdesk; dynamic-rule preview.

**EasyEntra comparison** (the owner wants to imitate it and do better; from easyentra.com, 2026-11-14). An
ADUC-style Windows console for on-prem AD + Entra: users, groups, licences, mailbox settings, MFA settings,
BitLocker, LAPS, user templates for onboarding, 20+ offboarding options, multi-tenant switching, delegated calendar
access, a PowerShell module. Not matched here: on-prem AD and Exchange/mailbox management (need more than Graph),
MFA management, saved templates. Ahead of it: PIM just-in-time elevation, a preview of every change, "who can
manage", administrative units, the security audit, and now the sync-rule validator.

## 5. Sync-rule tools (`auditor sync`, `toolkit/syncrules.py`): status

The owner keeps objects out of Entra by a designated OU and by `extensionAttribute14 = "no0365sync"`, and wants to
understand the rules, clean them up, and be sure a change "won't wildly change things" (a validator).

Built (offline: reads files, never signs in):
- `auditor sync describe <export>`: each rule in plain English (`--custom`, `--filters`).
- `auditor sync lint <export>`: duplicate precedence, a rule that filters everything, unknown operators, custom
  rules at precedence 100 or more, disabled rules. Exit code 1 on errors.
- `auditor sync explain <export> --set attr=value ...` (or `--csv file --who upn`): why an object is or isn't
  synchronised; `--excluded-ou` for OU filtering.
- `auditor sync diff <old> <new>`: changes, those that can alter who is synchronised first.
- `auditor sync impact <old> <new> <population.csv> [--max-changes N] [--max-percent P]`: who would start or stop
  synchronising; exit code 1 when over the limit or when anything can't be judged. This is the validator.

Not built / not known:
- **The export format is unconfirmed.** The reader uses the ADSync rule object's property names, loosely matched,
  and reports what it couldn't read. Test it on a real export first and fix `parse_rule`/`_scope`/`_flow`.
- OU filtering is connector configuration, not a rule: it is passed by hand (`--excluded-ou`); reading it from the
  export's connector files is not done.
- Expressions (`IIF(...)`) are shown, not evaluated: objects decided by one are "can't tell". Join rules,
  group-based filtering and outbound scoping other than `cloudFiltered` are not modelled.
- No editing or writing of rules, no desktop page, nothing for Cloud Sync (its scoping IS in Graph:
  synchronization jobs).
- "Explain" for a user who is NOT synchronised needs on-prem attributes (the object isn't in Entra), hence the CSV.

## 6. Not verified against a live tenant

Everything since 0.2.3 was built from the Graph v1.0 docs and tested only against fakes. Test in a real tenant
first (the owner's test tenant has no eligible roles, so PIM will be tested in production later):
- PIM activation and the elevation dialogs; PIM for Groups; unit-scoped roles in the elevation flow.
- Desktop sign-in (device code, browser), **Switch tenant** (a second `app.exec()` after a sign-in dialog), and the
  directory load at 300k objects (time, memory, the `userType`/`onPremisesSyncEnabled` filters).
- The assumption that permissions consented on the app registration but **not requested at sign-in** still appear in
  the token. Deliberately not in `TOOLKIT_SCOPES` (requesting an unconsented scope breaks every sign-in): PIM for
  Groups, `AdministrativeUnit.ReadWrite.All`, `Member.Read.Hidden`, `BitlockerKey.Read.All`,
  `DeviceLocalCredential.Read.All`.
- Administrative units (reads, member changes, the `directoryScopeId` filter with its `scopedRoleMembers` fallback).
- Groups page writes (add/remove members, owners, nesting) after the 0.2.3 fix.
- Licences (`licenseAssignmentStates` shape, `assignLicense`), offboarding, onboarding (create user; the
  replication retry; `PUT /users/{id}/manager/$ref` was NOT re-checked in the docs).
- Devices: listing BitLocker keys by `deviceId` (filter not re-checked in the docs), the `"value"` wrapper, LAPS
  base64 decoding (the docs' example decodes correctly).
- "Who can manage": `$filter=roleDefinitionId eq ..&$expand=principal` on roleAssignments and
  roleEligibilitySchedules; its rules are transcribed from Microsoft's tables and need re-checking when those change.
- Plus the older list in CLAUDE.md (certificate-ID writes, `$expand` at scale).

## 7. Documentation pages used (re-check with the docs skill)

- PIM: privilegedAccessGroup assignmentScheduleRequest; eligibilityScheduleInstance filterByCurrentUser
- administrativeUnit resource; add member; list members; list scopedRoleMembers
- List unifiedRoleAssignments (example: `$filter=roleDefinitionId eq ..&$expand=principal`); List roleEligibilitySchedules
- List a user's direct memberships / List group memberships (return administrative units; the cast needs advanced query)
- Assign Microsoft Entra roles, "administrative unit scope"; Restricted management administrative units
- Privileged roles and permissions ("Who can reset passwords", "Who can perform sensitive actions")
- Add members (which object types a security / Microsoft 365 group can hold)
- user: assignLicense; Create user
- Get bitlockerRecoveryKey (`$select=key` is audited); Get deviceLocalCredentialInfo (`$select=credentials`)
- List devices (`Device.Read.All` or `Directory.Read.All`; unit links use the object `id`, not `deviceId`)
- Not from Microsoft's docs: the Entra Connect export (`Get-ADSyncServerConfiguration -Path`) was confirmed only from
  community sources; its JSON layout was not found documented.

## 8. Working notes

- Look at every new screen: drive the real widgets against `FakeTenant` with `QT_QPA_PLATFORM=offscreen` and
  `widget.grab().save(...)`. This caught: Enter applying a change, the preview cutting off request bodies, a table
  hiding its key column in the narrow property pane, an unwrapped dialog heading, a truncated column.
- Benchmark anything that touches "all users" at 300k (there is a regression test in `tests/test_gui_basics.py`).
- Qt rules: worker results go through `gui/tasks.py TaskRunner`; no network on the UI thread; `dialog.open()` +
  `finished`, not `exec()`; `QMessageBox` statics are monkeypatched in tests.
- `FakeTenant` knobs added this round: `add_role_holder`, `add_scoped_eligibility`, `add_sku`/`give_licence`,
  `bitlocker`/`laps`, `managers`, `refuse`/`break_paths` (403/500 on matching write paths), `replication_misses`,
  `memberof_denied`, `unreadable_groups`, `skus_denied`, `secrets_denied`.
- When a tool call that writes this file is rejected, re-check before committing: one commit (`7738fb0`) claimed
  to rewrite it when the write had failed.
- Commits end with the attribution line from the session's instructions; keep model names out of commits.
