"""Fakes that duck-type ``GraphClient``. No network, no credentials.

``FakeTenant``  a small tenant (users, groups, PIM) that ENFORCES permissions the way Entra does:
                writes are denied until a PIM role is activated, and a freshly activated role can
                take a moment to take effect (``propagation_delay``).
``FakeGraph``   dictionary-backed: path -> list | dict | Exception | callable(kwargs).
"""
import re
from entra_auditor.graph.client import GraphError, GraphNotFoundError, GraphPermissionError, GraphResponse
BASE = 'https://graph.microsoft.com/v1.0'
LIT = re.compile("'((?:[^']|'')*)'")

def lits(text):
    return [m.replace("''", "'") for m in LIT.findall(text or '')]

def U(i, name, upn, **kw):
    d = {'id': i, 'displayName': name, 'userPrincipalName': upn, 'mail': upn, 'userType': 'Member', 'accountEnabled': True, 'mailNickname': upn.split('@')[0], 'createdDateTime': '2024-01-02T03:04:05Z', 'proxyAddresses': ['SMTP:' + upn], 'otherMails': [], 'assignedLicenses': []}
    d.update(kw)
    return d

def G(i, name, **kw):
    d = {'id': i, 'displayName': name, 'mailEnabled': False, 'securityEnabled': True, 'groupTypes': []}
    d.update(kw)
    return d

class FakeTenant:
    base_url = BASE
    ROLE_FOR_WRITES = {'User Administrator', 'Groups Administrator', 'Helpdesk Administrator', 'Privileged Authentication Administrator', 'Global Administrator', 'Authentication Administrator'}

    def __init__(self, *, propagation_delay=0, require_mfa=(), eligible=('User Administrator', 'Groups Administrator', 'Global Reader')):
        self.users = {u['id']: u for u in [U('u-alice', 'Alice Ng', 'alice@contoso.com', employeeId='E100', jobTitle='Engineer', department='IT', proxyAddresses=['SMTP:alice@contoso.com', 'smtp:a.ng@contoso.com'], otherMails=['alice@home.example']), U('u-bob', 'Bob Stone', 'bob@contoso.com'), U('u-bob2', 'Bob Smith', 'bob.smith@contoso.com'), U('u-guest', 'Partner Guest', 'partner_x.com#EXT#@contoso.onmicrosoft.com', userType='Guest', mail='partner@x.com'), U('u-sync', 'Sync Sam', 'sam@contoso.com', onPremisesSyncEnabled=True), U('u-admin', 'Ada Admin', 'ada@contoso.com'), U('u-obrien', "Pat O'Brien", 'pat@contoso.com'), U('11111111-2222-3333-4444-555555555555', 'Gina Guid', 'gina@contoso.com')]}
        self.groups = {g['id']: g for g in [G('g-fin', 'Finance Share'), G('g-dyn', 'Dynamic IT', groupTypes=['DynamicMembership'], membershipRule='user.department -eq "IT"'), G('g-mes', 'Mail-Sec', mailEnabled=True), G('g-sync', 'AD Group', onPremisesSyncEnabled=True), G('g-role', 'Role Group', isAssignableToRole=True), G('g-m365', 'Project X', groupTypes=['Unified'], mailEnabled=True, securityEnabled=False)]}
        self.members = {'g-fin': {'u-bob'}, 'g-m365': {'u-alice'}, 'g-role': set()}
        self.owners = {'g-fin': {'u-bob'}, 'g-m365': set()}
        self.certs = {'u-alice': ['X509:<PN>alice@contoso.com']}
        self.eligible_names = list(eligible)
        self.active_roles = {}
        self.require_mfa = set(require_mfa)
        self.propagation = propagation_delay
        self._denied_after_activation = 0
        self.calls, self.writes, self.filters = ([], [], [])
        self.reset_polls = 0
        self.role_ids = {n: f"r-{n.lower().replace(' ', '-')}" for n in list(eligible) + ['Helpdesk Administrator', 'Global Administrator']}
        # PIM for Groups (opt-in; see add_pim_group): eligible (group id, access), active {(gid, access): type},
        # and the directory roles each group holds
        self.group_eligible = []
        self.group_active = {}
        self.group_roles = {}

    def add_pim_group(self, gid, name, roles=(), access='member', role_assignable=True):
        """A group you are eligible for (membership by default) that holds `roles`."""
        self.groups[gid] = G(gid, name, isAssignableToRole=role_assignable)
        self.group_eligible.append((gid, access))
        self.group_roles[gid] = list(roles)
        return self

    def _granted_by_groups(self):
        return {r for (gid, access) in self.group_active if access == 'member' for r in self.group_roles.get(gid, [])}

    # ---- permission model: writes need an activated role (after any propagation delay) ----
    def _need_role(self):
        if not self.active_roles and not (self._granted_by_groups() & self.ROLE_FOR_WRITES):
            raise GraphPermissionError('Authorization_RequestDenied: Insufficient privileges to complete the operation.', status_code=403, code='Authorization_RequestDenied')
        if self._denied_after_activation > 0:
            self._denied_after_activation -= 1
            raise GraphPermissionError('Authorization_RequestDenied: role not yet effective.', status_code=403, code='Authorization_RequestDenied')

    # ---- the GraphClient surface the toolkit uses ----
    def get_all(self, path, **kw):
        return list(self.get_paged(path, **kw))

    def get_paged(self, path, **kw):
        self.calls.append(('GET', path))
        flt, params = (kw.get('filter') or '', kw.get('params') or {})
        if flt:
            self.filters.append(flt)
        if path == '/users':
            yield from self._users(flt, params, kw.get('top', 999))
            return
        if path == '/groups':
            yield from self._groups(flt, params)
            return
        if path == '/servicePrincipals':
            return
        m = re.match('/(users|groups)/([^/]+)/(\\w+)$', path)
        if m:
            kind, oid, edge = m.groups()
            if kind == 'groups' and edge in ('members', 'owners'):
                store = self.members if edge == 'members' else self.owners
                for uid in sorted(store.get(oid, set())):
                    yield {**self.users[uid], '@odata.type': '#microsoft.graph.user'}
                return
            if kind == 'users' and edge == 'memberOf':
                for gid, ms in self.members.items():
                    if oid in ms:
                        yield {**self.groups[gid], '@odata.type': '#microsoft.graph.group'}
                return
            if kind == 'users' and edge == 'ownedObjects':
                for gid, ms in self.owners.items():
                    if oid in ms:
                        yield {'id': gid, 'displayName': self.groups[gid]['displayName'], '@odata.type': '#microsoft.graph.group'}
                return
        if re.match('/users/([^/]+)/authentication/methods$', path):
            yield {'@odata.type': '#microsoft.graph.passwordAuthenticationMethod', 'id': 'pw'}
            yield {'@odata.type': '#microsoft.graph.phoneAuthenticationMethod', 'id': 'ph'}
            return
        if path.startswith('/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances/filterByCurrentUser'):
            for gid, access in self.group_eligible:
                yield {'groupId': gid, 'accessId': access, 'principalId': 'u-me', 'memberType': 'Direct',
                       'startDateTime': '2026-01-01T00:00:00Z', 'endDateTime': '2027-01-01T00:00:00Z'}
            return
        if path.startswith('/identityGovernance/privilegedAccess/group/assignmentScheduleInstances/filterByCurrentUser'):
            for (gid, access), kind in self.group_active.items():
                yield {'groupId': gid, 'accessId': access, 'principalId': 'u-me', 'assignmentType': kind,
                       'endDateTime': '2026-10-06T10:00:00Z'}
            return
        if path == '/roleManagement/directory/roleAssignments' and any(g in flt for g in self.group_roles):
            for gid, names in self.group_roles.items():
                if gid in flt:
                    for n in names:
                        yield {'roleDefinitionId': self.role_ids.get(n, n), 'roleDefinition': {'displayName': n}}
            return
        if path in ('/roleManagement/directory/roleAssignments', '/roleManagement/directory/roleEligibilitySchedules'):
            if 'u-admin' in flt:
                yield {'roleDefinitionId': 'r-ga', 'roleDefinition': {'displayName': 'Global Administrator'}}
            return
        if path.startswith('/roleManagement/directory/roleEligibilitySchedules/filterByCurrentUser'):
            for n in self.eligible_names:
                yield {'roleDefinitionId': self.role_ids[n], 'roleDefinition': {'displayName': n}, 'directoryScopeId': '/', 'scheduleInfo': {'expiration': {'endDateTime': '2027-01-01T00:00:00Z'}}}
            return
        if path.startswith('/roleManagement/directory/roleAssignmentScheduleInstances/filterByCurrentUser'):
            for rid, n in self.active_roles.items():
                yield {'roleDefinitionId': rid, 'roleDefinition': {'displayName': n}, 'directoryScopeId': '/', 'assignmentType': 'Activated', 'endDateTime': '2026-10-06T10:00:00Z'}
            return
        if path == '/roleManagement/directory/roleDefinitions':
            for n, rid in self.role_ids.items():
                yield {'id': rid, 'displayName': n}
            return
        raise AssertionError(f'FakeTenant.get_paged: unhandled {path}')

    def get(self, path, **kw):
        self.calls.append(('GET', path))
        if path.startswith('http'):
            path = path.replace(BASE, '')
        if path == '/me':
            return {'id': 'u-me', 'userPrincipalName': 'me@contoso.com'}
        m = re.match('/users/([^/]+)$', path)
        if m:
            uid = m.group(1)
            if uid not in self.users:
                raise GraphNotFoundError('404 not found', status_code=404)
            u = self.users[uid]
            sel = kw.get('select') or []
            if sel == ['signInActivity']:
                return {'signInActivity': {'lastSignInDateTime': '2026-09-30T08:00:00Z', 'lastNonInteractiveSignInDateTime': '2026-10-01T09:00:00Z'}}
            if sel == ['authorizationInfo']:
                return {'authorizationInfo': {'certificateUserIds': list(self.certs.get(uid, []))}}
            return dict(u)
        if re.match('/users/([^/]+)/manager$', path):
            return {'displayName': 'Mia Manager'}
        m = re.match('/groups/([^/]+)$', path)
        if m:
            if m.group(1) not in self.groups:
                raise GraphNotFoundError('404', status_code=404)
            return dict(self.groups[m.group(1)])
        m = re.match('/users/[^/]+/authentication/operations/(\\w+)$', path)
        if m:
            self.reset_polls += 1
            return {'status': 'running' if self.reset_polls < 2 else 'succeeded'}
        raise AssertionError(f'FakeTenant.get: unhandled {path}')

    def request(self, method, path, *, json=None, **kw):
        self.calls.append((method, path))
        if path.startswith('http'):
            path = path.replace(BASE, '')
        if path == '/roleManagement/directory/roleAssignmentScheduleRequests':
            return self._pim(json)
        if path == '/identityGovernance/privilegedAccess/group/assignmentScheduleRequests':
            return self._group_pim(json)
        self.writes.append((method, path, json))
        self._need_role()
        m = re.match('/groups/([^/]+)/(members|owners)/\\$ref$', path)
        if m and method == 'POST':
            gid, edge = m.groups()
            uid = json['@odata.id'].rsplit('/', 1)[-1]
            store = self.members if edge == 'members' else self.owners
            if uid in store.setdefault(gid, set()):
                raise GraphError("One or more added object references already exist for the following modified properties: 'members'.", status_code=400)
            store[gid].add(uid)
            return GraphResponse(204)
        m = re.match('/groups/([^/]+)/(members|owners)/([^/]+)/\\$ref$', path)
        if m and method == 'DELETE':
            gid, edge, uid = m.groups()
            store = self.members if edge == 'members' else self.owners
            if uid not in store.get(gid, set()):
                raise GraphError('not a member', status_code=404)
            store[gid].remove(uid)
            return GraphResponse(204)
        m = re.match('/users/([^/]+)$', path)
        if m and method == 'PATCH':
            uid = m.group(1)
            for k, v in json.items():
                if k == 'authorizationInfo':
                    self.certs[uid] = list(v['certificateUserIds'])
                else:
                    self.users[uid][k] = v
            return GraphResponse(204)
        m = re.match('/users/([^/]+)/authentication/methods/[\\w-]+/resetPassword$', path)
        if m:
            self.reset_polls = 0
            body = {} if (json or {}).get('newPassword') else {'newPassword': 'Gen3rated!Pw42'}
            return GraphResponse(202, {'location': f'{BASE}/users/{m.group(1)}/authentication/operations/op1'}, body)
        if path.endswith('/revokeSignInSessions'):
            return GraphResponse(200, {}, {'value': True})
        raise AssertionError(f'FakeTenant.request: unhandled {method} {path}')

    def post(self, path, json=None, **kw):
        return self.request('POST', path, json=json)

    def patch(self, path, json, **kw):
        return self.request('PATCH', path, json=json)

    def delete(self, path, **kw):
        return self.request('DELETE', path)

    def _pim(self, body):
        self.writes.append(('POST', 'pim', body))
        name = next((n for n, rid in self.role_ids.items() if rid == body['roleDefinitionId']), None)
        if body['action'] == 'selfDeactivate':
            self.active_roles.pop(body['roleDefinitionId'], None)
            return GraphResponse(201, {}, {'id': 'req2', 'status': 'Revoked'})
        if name not in self.eligible_names:
            raise GraphPermissionError('403 not eligible', status_code=403, code='Authorization_RequestDenied')
        if name in self.require_mfa:
            raise GraphError('The following policy rules failed: ["MfaRule"]', status_code=400, code='RoleAssignmentRequestPolicyValidationFailed')
        if not body.get('justification'):
            raise GraphError('The following policy rules failed: ["JustificationRule"]', status_code=400, code='RoleAssignmentRequestPolicyValidationFailed')
        if name in self.ROLE_FOR_WRITES:
            self.active_roles[body['roleDefinitionId']] = name
            self._denied_after_activation = self.propagation
        else:
            self.active_roles[body['roleDefinitionId']] = name
        return GraphResponse(201, {}, {'id': 'req1', 'status': 'Granted'})

    def _group_pim(self, body):
        self.writes.append(('POST', 'group-pim', body))
        key = (body['groupId'], body['accessId'])
        if body['action'] == 'selfDeactivate':
            self.group_active.pop(key, None)
            return GraphResponse(201, {}, {'id': 'greq2', 'status': 'Revoked'})
        if key not in self.group_eligible:
            raise GraphPermissionError('403 not eligible', status_code=403, code='Authorization_RequestDenied')
        if not body.get('justification'):
            raise GraphError('The following policy rules failed: ["JustificationRule"]', status_code=400,
                             code='RoleAssignmentRequestPolicyValidationFailed')
        self.group_active[key] = 'activated'
        if self._granted_by_groups() & self.ROLE_FOR_WRITES:
            self._denied_after_activation = self.propagation
        return GraphResponse(201, {}, {'id': 'greq1', 'status': 'Provisioned'})

    def _users(self, flt, params, top):
        vals = lits(flt)
        out = []
        for u in self.users.values():
            if 'proxyAddresses/any' in flt:
                ok = any((v in u['proxyAddresses'] for v in vals))
            elif 'otherMails/any' in flt:
                ok = any((v in u['otherMails'] for v in vals))
            elif 'startswith' in flt:
                ok = any(((u.get(f) or '').lower().startswith(vals[0].lower()) for f in ('userPrincipalName', 'mail', 'displayName')))
            elif 'userPrincipalName eq' in flt:
                ok = any((v.lower() in ((u['userPrincipalName'] or '').lower(), (u['mail'] or '').lower()) for v in vals))
            elif 'mailNickname eq' in flt:
                ok = any((v.lower() == u['mailNickname'].lower() or v == u.get('employeeId') for v in vals))
            elif 'mail eq' in flt:
                ok = any((v.lower() == (u['mail'] or '').lower() for v in vals))
            elif 'employeeId eq' in flt:
                ok = any((v == u.get('employeeId') for v in vals))
            elif params.get('$search'):
                term = re.search('displayName:(.*?)"', params['$search']).group(1).replace('\\"', '"').replace('\\\\', '\\').lower()
                ok = any((w.lower().startswith(term) for w in (u['displayName'] or '').split())) or term in (u['userPrincipalName'] or '').lower()
            else:
                ok = True
            if ok:
                out.append(dict(u))
        return out

    def _groups(self, flt, params):
        vals = lits(flt)
        out = []
        for g in self.groups.values():
            name = g['displayName'].lower()
            if 'startswith' in flt:
                ok = name.startswith(vals[0].lower())
            elif 'displayName eq' in flt:
                ok = name == vals[0].lower()
            elif 'mail eq' in flt:
                ok = False
            elif params.get('$search'):
                term = re.search('displayName:(.*?)"', params['$search']).group(1).lower()
                ok = term in name
            else:
                ok = True
            if ok:
                out.append(dict(g))
        return out

class FakeGraph:
    """path -> list | dict | Exception | callable(kwargs). Unknown paths fail the test loudly."""
    base_url = BASE

    def __init__(self, data=None):
        self.data, self.calls = (dict(data or {}), [])

    def _value(self, path, kw):
        self.calls.append((path, kw))
        if path not in self.data:
            raise AssertionError(f'FakeGraph: unexpected request to {path}')
        value = self.data[path]
        if callable(value):
            value = value(kw)
        if isinstance(value, Exception):
            raise value
        return value

    def get_all(self, path, **kw):
        return list(self._value(path, kw))

    def get_paged(self, path, **kw):
        yield from self._value(path, kw)

    def get(self, path, **kw):
        return self._value(path, kw)
