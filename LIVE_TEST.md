# First live test: checklist

Ordered from harmless to risky. Stop at any step that surprises you. Nothing in phase 1 can change the tenant.
Everything in this app was built from Microsoft's documentation and tested only against a simulated tenant,
so expect some failures: each one you report is worth more than a dozen passing tests.

## 0. Before you start

- [ ] Install: `python -m pip install ".[gui]"` (Python 3.10 or later). Run `auditor gui` from a terminal
      inside your desktop session, not over plain SSH. On Linux, Qt also needs `libxcb-cursor`
      (Arch: `sudo pacman -S xcb-util-cursor`; Debian/Ubuntu: `sudo apt install libxcb-cursor0`).
- [ ] App registration: **Allow public client flows** = Yes; platform **Mobile and desktop applications** with
      redirect URI `http://localhost`; the **delegated** permissions in README "Setup for the toolkit", with
      admin consent. Optional ones (PIM for Groups, `AdministrativeUnit.ReadWrite.All`, `BitlockerKey.Read.All`,
      `DeviceLocalCredential.Read.All`, `Member.Read.Hidden`) can be added now or after step 1.3.
- [ ] Copy `tenants.example.json` to `~/.entra_auditor/tenants.json`, put in your tenant and app ids, and set
      `"read_only": true`. For your large tenant, also set `"user_scope"` (for example `"synced"`) and
      `"hide_external": true` so the first load isn't 300,000 objects.
- [ ] Pick a **test user you own** (not a real person's account) for phase 2.

## 1. Read-only (no risk)

Start `auditor gui`. Check that the sign-in screen shows "Read-only" ticked and the window says READ-ONLY.

1. [ ] Sign in with **device code**. Then Switch tenant and sign in again with **browser**.
2. [ ] Note how long the user list takes to load (status bar) and roughly how many users. Try each load choice
       (all / members / guests / synced) and "Hide external". Is typing in the filter instant? Is sorting?
3. [ ] **Tenant check** page: let it run, press **Copy report**, and keep the text. This is the single most useful
       thing to send back. It names no user or tenant.
4. [ ] Open a few users, including a synced one and an admin. Look at every tab: General, **On-premises**
       (does the AD location look right?), Groups, **Licences** (direct vs from group), Sign-in methods,
       Certificate IDs, Roles, **Who can manage** (does it match what you know about your delegation?).
5. [ ] **Groups**: a security group, a Microsoft 365 group, a dynamic group, a synced group. Members, owners,
       Member of. Are Exchange-managed groups hidden until ticked?
6. [ ] **Administrative units**: does the tree show Users / Groups / Devices with sensible counts? A restricted
       unit? Scoped roles on the Roles tab?
7. [ ] **Devices**: list and properties. "Find BitLocker recovery keys" only lists keys. Showing a key or a LAPS
       password is a read but it is audited by Entra: do it on a test device only, if at all.
8. [ ] **Roles / PIM**: are your eligible roles and PIM groups listed correctly?

## 2. Changes (on your test user only)

Sign in again with "Read-only" unticked. Every change shows a preview first; Cancel is the default.

1. [ ] Disable, then enable the test user.
2. [ ] Licences tab: assign a licence, then remove it.
3. [ ] Groups page: add the test user to a test group, then remove them.
4. [ ] **PIM elevation**: sign in WITHOUT the needed role active, try a change, and follow the offered
       activation (role choice, justification, wait, retry). This path has never run against Entra.
5. [ ] Reset the test user's password (the new one is shown once).
6. [ ] Sign-in methods tab: **Create Temporary Access Pass** for the test user (needs TAP enabled in your
       Authentication methods policy). Does the pass appear once, and does it work at sign-in?
7. [ ] **New user...** with the test user selected (modelled on it); check groups, licences and manager.
8. [ ] **Offboard...** the new user from step 7. Check the step-by-step result.

## 3. Offline sync-rule tools (no tenant access)

On a machine with your Entra Connect export (`Get-ADSyncServerConfiguration -Path <folder>`):
`auditor sync describe <folder> --custom`, `auditor sync lint <folder>`, and `auditor sync explain` for a user
you know is filtered. Report anything that reads oddly or says "can't tell".

## What to send back

- The Tenant check report (step 1.3).
- For each step: worked / didn't, plus the message shown. Replace names before sharing.
- Load time and rough user count from step 1.2; anything that felt slow.
- Anything confusing in the wording or layout, however small.
