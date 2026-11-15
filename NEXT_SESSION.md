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
   QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -o addopts=""    # 1012 passed (the default addopts hide the summary)
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
| User tabs | `gui/user_detail.py` | General, **On-premises** (the synced copy of the AD record: OU path, logon name, DN, SID, source anchor, last sync, extensionAttribute1-15, sync errors), Groups (double-click opens the group), **Licences** (lazy; assign/remove), Sign-in methods, Certificate IDs, Roles, **Who can manage** (lazy, read-only) |
| **New user...** | `gui/onboarding.py`, `toolkit/onboarding.py` | modelled on the selected user; password shown once |
| **Offboard...** | `gui/leaver.py`, `toolkit/leaver.py` | one multi-step plan; reports each step |
| Enable/disable | toolbar | |
| **Groups** | `gui/groups_page.py`, `toolkit/groups.py` | members, owners, nested security groups, memberOf; Exchange-managed hidden by default |
| **Devices** | `gui/devices_page.py`, `toolkit/devices.py` | BitLocker keys and LAPS passwords on request, shown once |
| **Administrative units** | `gui/admin_units_page.py`, `toolkit/admin_units.py` | a two-level tree: unit, then Users / Groups / Devices nodes (counts once opened; a node filters the member table without reloading); settings, scoped roles |
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

- **Sync rules:** the owner CANNOT export their configuration to us (proprietary). Don't ask for it; ask them to run
  `auditor sync describe|lint` on their own export and report what looks wrong or says "can't tell" (section 5).
- **Which load scope is "their 30k users"?** Tenant: ~30k users, 300k+ user objects (guests, cross-tenant sync).
  Default is still "all users"; `tenants.json` can set `user_scope` and `hide_external`. Hiding `#EXT#` is done while
  loading (Graph has no server-side `contains` on the UPN), so those pages are still downloaded. A server-side
  variant (`not endswith(userPrincipalName, '#EXT#@<initial domain>')` as an advanced query) is untested.
- **On-premises AD over LDAP** (owner's idea, 2026-11-15: "ADUC-style LDAP", the entire record for objects that
  exist on both sides; for domain admins and power users). NOT built: the On-premises tab shows only what Entra
  holds. A live AD connection is a real step up in scope and risk, so decide first:
  1. read-only (show the full AD record, group memberships, OU tree) or also writes (unlock, reset, move, edit)?
  2. how to authenticate: the signed-in Windows user (Kerberos/SSPI; Windows-only, no password handled), or a
     prompt for domain credentials (kept in memory only, like tokens)? LDAPS/Kerberos sealing only, never simple
     bind in clear text.
  3. dependency: `ldap3` (pure Python) as another optional extra, like `.[gui]`.
  4. it can't be tested here beyond a fake directory; the owner would have to try it on a domain-joined machine.
  Suggested first cut: read-only, optional extra, "Active Directory" section added to the On-premises tab (all
  attributes, memberOf, lockout/password state, last logon), matched by the source anchor / objectGUID.
- **Role assignment writes** (assign admin roles, tenant-wide or unit-scoped): still undecided. Options: stay
  read-only [recommended until PIM is tested live], PIM-eligible only, or eligible and permanent. Offboarding
  therefore lists admin roles but does not remove them.
- **Licence** for the repo: `LICENSE` was deleted on purpose; don't add one until the owner chooses.
- Sync engine (answered): Entra Connect Sync primarily; a Cloud Sync connector also exists.

## 4. What to build next

Agreed order so far; items 1-5 of the EasyEntra list are done except the last:
1. **Sign-in method management** (Temporary Access Pass, removing methods): NOT STARTED. Check the docs per method
   type first (each type has its own delete endpoint; TAP is a POST on `temporaryAccessPassMethods`).
2. **Sync rules, next steps** (section 5): the owner's feedback from running it on their own export; an attribute
   list for the population CSV; proposing/validating a rule change; then a desktop page.
3. **Scale follow-ups:** the Groups and Devices pages and the pickers still use `QTableWidget`/`QListWidget` and will
   be slow with tens of thousands of rows (give them the `UserFilterProxy` treatment); 300k `UserSummary` objects cost
   ~650 MB (slimmer rows would fix it).
4. **Gaps left in finished features:** create/delete/edit a group; licence service-plan toggles and a tenant-wide
   subscriptions view; device enable/disable/delete and a user's devices on the user's tabs; "who can manage this
   group"; expand a group principal to its members in "Who can manage"; custom roles there; use the restricted-unit
   knowledge in the elevation flow (don't offer a tenant-wide role for a target in a restricted unit); CLI commands
   for offboarding/onboarding/licences.
   Sync tie-in idea: with a Connect export loaded, the On-premises tab could explain "why is this user synced /
   what would filter it" using the user's own extension attributes and DN (`syncrules.verdict`).
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

## 5. Sync-rule tools (`auditor sync`; `toolkit/syncrules.py`, `syncexpr.py`, `syncrules_cli.py`): status

The owner (Entra Connect Sync, plus a Cloud Sync connector) wants to understand the rules, clean them up, and be
sure a change "won't wildly change things": a validator. It must be **agnostic** (nothing tied to their own
convention of an excluded OU and `extensionAttribute14 = "no0365sync"`), and **they cannot hand over an export**
(proprietary). So the tool is built and tested on Microsoft's published sample instead, and runs only on their own
machine against their own files.

Built (offline: reads files, never signs in):
- Reader for the real format: the XML folder written by `Get-ADSyncServerConfiguration -Path`
  (`SynchronizationRules/*.xml`, `Connectors/*.xml`). Connector GUIDs are resolved to names. JSON
  (`Get-ADSyncRule | ConvertTo-Json`) is still accepted but its shape is unconfirmed.
- Container (OU) filtering read from the connectors: per partition, included and excluded containers; the most
  specific one wins (`ContainerFilter`).
- `cloudFiltered` decided in precedence order, NULL passing to the next rule; expressions evaluated by
  `syncexpr.py` (IIF, IsPresent, IsNullOrEmpty, Left/Right/Mid, InStr, BitAnd/BitOr, CBool/CStr/CNum, Trim, Len,
  DNComponent/CRef, Contains, ValueCount; `&&`, `||`, comparisons, `&`). Anything else is UNKNOWN.
- Commands: `describe` (`--custom`, `--filters`), `lint`, `explain` (`--set a=b` or `--csv file --who upn`),
  `diff` (includes container changes), `impact <old> <new> <population.csv> [--max-changes N] [--max-percent P]`
  (exit code 1 over the limit or when anything can't be judged).
- Test data: `tests/data/connect_sample` = Microsoft's AADConnectConfigDocumenter sample (MIT, licence included):
  62 default rules unchanged, connectors trimmed to id/name/partition filters.

Not built / not known:
- Never run against a live Connect server or a current Connect version (the sample is an older default rule set).
- Only container filtering and `cloudFiltered` are modelled. Not: the outbound rules' other scope conditions (a
  group or contact needs more than "not cloudFiltered" to be exported), join rules, group-based filtering,
  domain/attribute filtering done other ways, attribute precedence for other attributes.
- Unimplemented expression functions give "can't tell" (Word, Item, Error, StringFromSid, RemoveDuplicates, ...).
  Assumptions to verify: string comparison is case-insensitive; `DNComponent(x, 1)` is the leftmost component.
- No editing/writing of rules (the owner mentioned "modify/clean it up"): next step could be generating a proposed
  rule (as the PowerShell `New-ADSyncRule ...` commands) and validating it with `impact` before it is applied.
- No desktop page; nothing for Cloud Sync (its scoping IS in Graph: synchronization jobs).
- Ideas: a `--csv` template command that lists every AD attribute the rules and expressions reference (so the
  population export has the right columns); clean-up hints (rules that never match the population, disabled clones,
  overlapping filters); reading `GlobalSettings`.

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
- Entra Connect export: not from the docs but from Microsoft's own sample in
  github.com/microsoft/AADConnectConfigDocumenter (`src/SolutionOutput/Data/Contoso`, MIT): XML, not JSON.

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
- Commit only on a green run: chain with `&&` (`pytest ... && git commit ...`). Commit `faac2a3` went in after a run
  that had segfaulted, because only the last output line was looked at. The cause (two thread/lifetime bugs in
  `gui/tasks.py` and `gui/change.py`, see CLAUDE.md) was fixed in the next commit; the suite then passed 8 runs in
  a row. If a run ever ends in a "Fatal Python error" dump again, treat it as a real bug, not as flakiness.
- Config files (2026-11-15, the owner thought they were dead): `requirements.txt` IS used (pyproject reads it; CI
  installs through `requirements-dev.txt`), `.env.example` documents every environment variable the code reads,
  and `tenants.example.json` is the desktop app's template. Three tests keep them in step with the code. When a
  setting or dependency is added, update the example file in the same commit or those tests fail.
- When a tool call that writes this file is rejected, re-check before committing: one commit (`7738fb0`) claimed
  to rewrite it when the write had failed.
- Commits end with the attribution line from the session's instructions; keep model names out of commits.
