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
    ROLE_FOR_WRITES = {'License Administrator', 'Privileged Role Administrator', 'User Administrator', 'Groups Administrator', 'Helpdesk Administrator', 'Privileged Authentication Administrator', 'Global Administrator', 'Authentication Administrator'}

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
        # administrative units (opt-in; see add_admin_unit)
        self.admin_units = {}
        self.au_members = {}
        self.au_roles = []           # (au id, role name, principal id, 'active'|'eligible')
        self.au_scope_filter_supported = True
        # PIM roles scoped to an administrative unit (opt-in; see add_scoped_eligibility):
        # eligible [(role name, au id)], active {(role id, scope): role name}
        self.scoped_eligible = []
        self.scoped_active = {}
        self.group_role_scope = {}   # group id -> directoryScopeId of the roles it holds (default '/')
        # licences (opt-in; see add_sku / give_licence): subscriptions, and per user {sku id: {'direct', 'groups'}}
        self.skus = {}
        self.licences = {}
        self.skus_denied = False
        self.managers = {}               # user id -> manager's user id
        self.replication_misses = 0      # how many requests about a just-created user answer 404 first
        self.created = []                # ids of users created through POST /users
        self.refuse = []                 # regexes: a write whose path matches answers 403 (needs a higher role)
        self.break_paths = []            # regexes: a write whose path matches answers 500
        self.unreadable_groups = set()   # group ids whose members/owners answer 403
        self.memberof_denied = False # True: memberOf answers 403 (the target's AUs can't be read)
        # who holds which admin role (opt-in; see add_role_holder): (role, principal id, scope, 'active'|'eligible')
        self.role_holders = []
        self.assignments_denied = False     # True: listing role assignments by role answers 403
        self.eligibility_denied = False     # True: listing eligibility schedules by role answers 403
        # device objects: id = directory object id, deviceId = hardware id (deliberately different)
        self.devices = {
            'dev-1': {'id': 'dev-1', 'deviceId': 'hw-1111', 'displayName': 'SEA-LT-001', 'operatingSystem': 'Windows',
                      'operatingSystemVersion': '10.0.26100', 'accountEnabled': True, 'trustType': 'AzureAd'},
            'dev-2': {'id': 'dev-2', 'deviceId': 'hw-2222', 'displayName': 'Pixel 8', 'operatingSystem': 'Android',
                      'operatingSystemVersion': '15', 'accountEnabled': True, 'trustType': 'Workplace'},
            'dev-3': {'id': 'dev-3', 'deviceId': 'hw-3333', 'displayName': 'OLD-PC', 'operatingSystem': 'Windows',
                      'operatingSystemVersion': '10.0.19045', 'accountEnabled': False, 'trustType': 'ServerAd'},
        }

    def add_pim_group(self, gid, name, roles=(), access='member', role_assignable=True, au=None):
        """A group you are eligible for (membership by default) that holds `roles`, tenant-wide or scoped
        to the administrative unit `au`."""
        self.groups[gid] = G(gid, name, isAssignableToRole=role_assignable)
        self.group_eligible.append((gid, access))
        self.group_roles[gid] = list(roles)
        if au:
            self.group_role_scope[gid] = f'/administrativeUnits/{au}'
        return self

    def add_sku(self, sku_id, part_number, total=10, status='Enabled', applies_to='User'):
        self.skus[sku_id] = {'skuId': sku_id, 'skuPartNumber': part_number, 'prepaidUnits': {'enabled': total},
                             'capabilityStatus': status, 'appliesTo': applies_to}
        return self

    def give_licence(self, user_id, sku_id, group=None):
        """Assign directly, or (with `group`) as inherited from that group."""
        held = self.licences.setdefault(user_id, {}).setdefault(sku_id, {'direct': False, 'groups': []})
        if group:
            held['groups'].append(group)
        else:
            held['direct'] = True
        return self

    def _consumed(self, sku_id):
        return sum(1 for held in self.licences.values() if sku_id in held)

    def _assign_license(self, uid, body):
        user, held = self.users[uid], self.licences.setdefault(uid, {})
        for sku_id in body['removeLicenses']:
            if not held.get(sku_id, {}).get('direct'):
                raise GraphError('User license is inherited from a group membership and it cannot be removed directly from the user.', status_code=400, code='Request_BadRequest')
        for item in body['addLicenses']:
            sku = self.skus.get(item['skuId'])
            if sku is None:
                raise GraphError('License assignment failed because service plan is invalid.', status_code=400, code='Request_BadRequest')
            if not user.get('usageLocation'):
                raise GraphError('License assignment cannot be done for user with invalid usage location.', status_code=400, code='Request_BadRequest')
            if item['skuId'] not in held and self._consumed(item['skuId']) >= sku['prepaidUnits']['enabled']:
                raise GraphError('Subscription does not have any available licenses.', status_code=400, code='Request_BadRequest')
        for sku_id in body['removeLicenses']:
            held[sku_id]['direct'] = False
            if not held[sku_id]['groups']:
                del held[sku_id]
        for item in body['addLicenses']:
            held.setdefault(item['skuId'], {'direct': False, 'groups': []})['direct'] = True
        return GraphResponse(200, {}, {'id': uid})

    def add_role_holder(self, role, principal_id, state='active', au=None):
        """Give a user or group an admin role, tenant-wide or scoped to the administrative unit `au`."""
        self.role_holders.append((role, principal_id, f'/administrativeUnits/{au}' if au else '/', state))
        self.role_ids.setdefault(role, f"r-{role.lower().replace(' ', '-')}")
        return self

    def _assignment(self, role, pid, scope):
        obj = self._object(pid)
        return {'roleDefinitionId': self.role_ids[role], 'roleDefinition': {'displayName': role}, 'principalId': pid,
                'directoryScopeId': scope,
                'principal': {'@odata.type': obj['@odata.type'], 'id': pid, 'displayName': obj.get('displayName'),
                              'userPrincipalName': obj.get('userPrincipalName')}}

    def add_scoped_eligibility(self, role, au_id):
        """Make the signed-in user eligible for `role` scoped to one administrative unit only."""
        self.scoped_eligible.append((role, au_id))
        self.role_ids.setdefault(role, f"r-{role.lower().replace(' ', '-')}")
        return self

    def _in_scope(self, scope, target):
        if scope in ('/', ''):
            return True
        au = scope.rsplit('/', 1)[-1]
        return scope.startswith('/administrativeUnits/') and target is not None and target in self.au_members.get(au, set())

    def _admin_units_of(self, oid):
        for au, members in self.au_members.items():
            if oid in members:
                yield {'id': au, 'displayName': self.admin_units[au]['displayName'],
                       'membershipType': self.admin_units[au].get('membershipType'),
                       '@odata.type': '#microsoft.graph.administrativeUnit'}

    def add_admin_unit(self, au_id, name, members=(), **props):
        self.admin_units[au_id] = {'id': au_id, 'displayName': name, 'description': props.pop('description', None),
                                   'membershipType': None, 'membershipRule': None,
                                   'membershipRuleProcessingState': None, 'isMemberManagementRestricted': None,
                                   'visibility': None, **props}
        self.au_members[au_id] = set(members)
        return self

    def _object(self, oid):
        if oid in self.users:
            return {**self.users[oid], '@odata.type': '#microsoft.graph.user'}
        if oid in self.groups:
            return {**self.groups[oid], '@odata.type': '#microsoft.graph.group'}
        if oid in self.devices:
            return {**self.devices[oid], '@odata.type': '#microsoft.graph.device'}
        return {'id': oid, '@odata.type': '#microsoft.graph.device', 'displayName': oid, 'operatingSystem': 'Windows',
                'accountEnabled': True}

    def _granted_by_groups(self, target=None):
        return {r for (gid, access) in self.group_active if access == 'member'
                and self._in_scope(self.group_role_scope.get(gid, '/'), target) for r in self.group_roles.get(gid, [])}

    # ---- permission model: writes need an activated role (after any propagation delay). A role scoped to
    # an administrative unit only counts when the object being changed (`target`) is a member of that unit;
    # it never counts for changing the unit itself ----
    def _need_role(self, target=None):
        scoped = any(self._in_scope(scope, target) for (_rid, scope) in self.scoped_active)
        if not self.active_roles and not scoped and not (self._granted_by_groups(target) & self.ROLE_FOR_WRITES):
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
        if path == '/devices':
            yield from (dict(d) for d in self.devices.values())
            return
        if path == '/subscribedSkus':
            if self.skus_denied:
                raise GraphPermissionError('Authorization_RequestDenied', status_code=403, code='Authorization_RequestDenied')
            for sku_id, sku in self.skus.items():
                yield {**sku, 'consumedUnits': self._consumed(sku_id)}
            return
        if path == '/directory/administrativeUnits':
            for au in self.admin_units.values():
                yield {k: v for k, v in au.items() if k in (kw.get('select') or au)}
            return
        m = re.match('/directory/administrativeUnits/([^/]+)/members$', path)
        if m:
            if m.group(1) not in self.admin_units:
                raise GraphNotFoundError('404', status_code=404)
            for oid in sorted(self.au_members[m.group(1)]):
                yield self._object(oid)
            return
        m = re.match('/directory/administrativeUnits/([^/]+)/scopedRoleMembers$', path)
        if m:
            for au, role, pid, state in self.au_roles:
                if au == m.group(1) and state == 'active':
                    yield {'id': f'srm-{pid}', 'roleId': f'dr-{role}', 'administrativeUnitId': au,
                           'roleMemberInfo': {'id': pid, 'displayName': self._object(pid).get('displayName')}}
            return
        if 'roleDefinitionId eq' in flt and path in ('/roleManagement/directory/roleAssignments',
                                                       '/roleManagement/directory/roleEligibilitySchedules'):
            want = 'active' if path.endswith('roleAssignments') else 'eligible'
            if self.assignments_denied or (want == 'eligible' and self.eligibility_denied):
                raise GraphPermissionError('Authorization_RequestDenied', status_code=403, code='Authorization_RequestDenied')
            rid = lits(flt)[0]
            for role, pid, scope, state in self.role_holders:
                if self.role_ids[role] == rid and state == want:
                    yield self._assignment(role, pid, scope)
            return
        if 'directoryScopeId' in flt and path in ('/roleManagement/directory/roleAssignments',
                                                   '/roleManagement/directory/roleEligibilitySchedules'):
            if not self.au_scope_filter_supported:
                raise GraphError('Unsupported query.', status_code=400, code='Request_UnsupportedQuery')
            want = 'active' if path.endswith('roleAssignments') else 'eligible'
            for au, role, pid, state in self.au_roles:
                if f'/administrativeUnits/{au}' in flt and state == want:
                    obj = self._object(pid)
                    rid = self.role_ids.setdefault(role, f"r-{role.lower().replace(' ', '-')}")
                    yield {'roleDefinitionId': rid, 'principalId': pid,
                           'directoryScopeId': f'/administrativeUnits/{au}',
                           'principal': {'id': pid, 'displayName': obj.get('displayName'),
                                         'userPrincipalName': obj.get('userPrincipalName')}}
            return
        m = re.match('/(users|groups)/([^/]+)/(\\w+)$', path)
        if m:
            kind, oid, edge = m.groups()
            if kind == 'groups' and edge in ('members', 'owners'):
                store = self.members if edge == 'members' else self.owners
                if oid in self.unreadable_groups:
                    raise GraphPermissionError('Authorization_RequestDenied', status_code=403, code='Authorization_RequestDenied')
                for uid in sorted(store.get(oid, set())):
                    yield self._object(uid)
                return
            if edge == 'memberOf' and self.memberof_denied:
                raise GraphPermissionError('Authorization_RequestDenied', status_code=403, code='Authorization_RequestDenied')
            if kind == 'users' and edge == 'memberOf':
                for gid, ms in self.members.items():
                    if oid in ms:
                        yield {**self.groups[gid], '@odata.type': '#microsoft.graph.group'}
                yield from self._admin_units_of(oid)
                return
            if kind == 'groups' and edge == 'memberOf':
                for gid, ms in self.members.items():
                    if oid in ms:
                        yield {**self.groups[gid], '@odata.type': '#microsoft.graph.group'}
                yield from self._admin_units_of(oid)
                return
            if kind == 'users' and edge == 'ownedObjects':
                for gid, ms in self.owners.items():
                    if oid in ms:
                        yield {**self.groups[gid], '@odata.type': '#microsoft.graph.group'}
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
                        yield {'roleDefinitionId': self.role_ids.get(n, n), 'roleDefinition': {'displayName': n},
                               'directoryScopeId': self.group_role_scope.get(gid, '/')}
            return
        if path in ('/roleManagement/directory/roleAssignments', '/roleManagement/directory/roleEligibilitySchedules'):
            if 'u-admin' in flt:
                yield {'roleDefinitionId': 'r-ga', 'roleDefinition': {'displayName': 'Global Administrator'}}
            want = 'active' if path.endswith('roleAssignments') else 'eligible'
            for role, pid, scope, state in self.role_holders:
                if pid in lits(flt) and state == want:
                    yield self._assignment(role, pid, scope)
            return
        if path.startswith('/roleManagement/directory/roleEligibilitySchedules/filterByCurrentUser'):
            for n in self.eligible_names:
                yield {'roleDefinitionId': self.role_ids[n], 'roleDefinition': {'displayName': n}, 'directoryScopeId': '/', 'scheduleInfo': {'expiration': {'endDateTime': '2027-01-01T00:00:00Z'}}}
            for n, au in self.scoped_eligible:
                yield {'roleDefinitionId': self.role_ids[n], 'roleDefinition': {'displayName': n},
                       'directoryScopeId': f'/administrativeUnits/{au}',
                       'scheduleInfo': {'expiration': {'endDateTime': '2027-01-01T00:00:00Z'}}}
            return
        if path.startswith('/roleManagement/directory/roleAssignmentScheduleInstances/filterByCurrentUser'):
            for rid, n in self.active_roles.items():
                yield {'roleDefinitionId': rid, 'roleDefinition': {'displayName': n}, 'directoryScopeId': '/', 'assignmentType': 'Activated', 'endDateTime': '2026-10-06T10:00:00Z'}
            for (rid, scope), n in self.scoped_active.items():
                yield {'roleDefinitionId': rid, 'roleDefinition': {'displayName': n}, 'directoryScopeId': scope,
                       'assignmentType': 'Activated', 'endDateTime': '2026-10-06T10:00:00Z'}
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
            if 'licenseAssignmentStates' in sel:
                held = self.licences.get(uid, {})
                states = [{'skuId': s, 'assignedByGroup': None, 'state': 'Active', 'error': 'None'}
                          for s, h in held.items() if h['direct']]
                states += [{'skuId': s, 'assignedByGroup': g, 'state': 'Active', 'error': 'None'}
                           for s, h in held.items() for g in h['groups']]
                return {'usageLocation': u.get('usageLocation'), 'licenseAssignmentStates': states,
                        'assignedLicenses': [{'skuId': s, 'disabledPlans': []} for s in held]}
            if sel == ['authorizationInfo']:
                return {'authorizationInfo': {'certificateUserIds': list(self.certs.get(uid, []))}}
            return dict(u)
        m = re.match('/users/([^/]+)/manager$', path)
        if m and m.group(1) in self.managers:
            boss = self.users[self.managers[m.group(1)]]
            return {'id': boss['id'], 'displayName': boss['displayName']}
        if m:
            return {'displayName': 'Mia Manager'}
        m = re.match('/groups/([^/]+)$', path)
        if m:
            if m.group(1) not in self.groups:
                raise GraphNotFoundError('404', status_code=404)
            return dict(self.groups[m.group(1)])
        m = re.match('/directory/administrativeUnits/([^/]+)$', path)
        if m:
            if m.group(1) not in self.admin_units:
                raise GraphNotFoundError('404', status_code=404)
            return dict(self.admin_units[m.group(1)])
        m = re.match('/directoryRoles/dr-(.+)$', path)
        if m:
            from urllib.parse import unquote
            return {'displayName': unquote(m.group(1))}
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
        target = re.match('/(?:users|groups)/([^/]+)', path)
        self._need_role(target.group(1) if target else None)
        if any(re.search(pattern, path) for pattern in self.refuse):
            raise GraphPermissionError('Authorization_RequestDenied: Insufficient privileges to complete the operation.', status_code=403, code='Authorization_RequestDenied')
        if any(re.search(pattern, path) for pattern in self.break_paths):
            raise GraphError('Service unavailable', status_code=500)
        if self.replication_misses > 0 and any(uid in path or uid in str(json) for uid in self.created):
            self.replication_misses -= 1
            raise GraphNotFoundError('Request_ResourceNotFound: Resource does not exist or one of its queried reference-property objects are not present.', status_code=404, code='Request_ResourceNotFound')
        if path == '/users' and method == 'POST':
            missing = [k for k in ('accountEnabled', 'displayName', 'mailNickname', 'userPrincipalName', 'passwordProfile') if k not in json]
            if missing or not json['passwordProfile'].get('password'):
                raise GraphError(f'A value is required for property {missing or "password"}', status_code=400, code='Request_BadRequest')
            if any(u['userPrincipalName'].lower() == json['userPrincipalName'].lower() for u in self.users.values()):
                raise GraphError('Another object with the same value for property userPrincipalName already exists.', status_code=400, code='Request_BadRequest')
            uid = f'new-{len(self.created) + 1}'
            self.users[uid] = U(uid, json['displayName'], json['userPrincipalName'],
                                **{k: v for k, v in json.items() if k not in ('displayName', 'userPrincipalName', 'passwordProfile')})
            self.passwords = getattr(self, 'passwords', {})
            self.passwords[uid] = json['passwordProfile']
            self.created.append(uid)
            return GraphResponse(201, {}, {'id': uid, 'userPrincipalName': json['userPrincipalName']})
        m = re.match('/users/([^/]+)/manager/\\$ref$', path)
        if m and method == 'PUT':
            self.managers[m.group(1)] = json['@odata.id'].rsplit('/', 1)[-1]
            return GraphResponse(204)
        m = re.match('/groups/([^/]+)/(members|owners)/\\$ref$', path)
        if m and method == 'POST':
            gid, edge = m.groups()
            uid = json['@odata.id'].rsplit('/', 1)[-1]
            store = self.members if edge == 'members' else self.owners
            if uid in self.groups and ('Unified' in self.groups[gid].get('groupTypes', [])
                                       or 'Unified' in self.groups[uid].get('groupTypes', []) or edge == 'owners'):
                raise GraphError('Request_BadRequest: unsupported reference', status_code=400, code='Request_BadRequest')
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
        m = re.match('/directory/administrativeUnits/([^/]+)/members/\\$ref$', path)
        if m and method == 'POST':
            au = self.admin_units[m.group(1)]
            oid = json['@odata.id'].rsplit('/', 1)[-1]
            if (au.get('membershipType') or '').lower() == 'dynamic':
                raise GraphError('Members of a dynamic administrative unit cannot be managed manually.', status_code=400)
            if au.get('isMemberManagementRestricted') and oid in self.groups and (
                    self.groups[oid].get('mailEnabled') or 'Unified' in self.groups[oid].get('groupTypes', [])):
                raise GraphError('This group type cannot be added to a restricted administrative unit.', status_code=400)
            if oid in self.au_members[m.group(1)]:
                raise GraphError("One or more added object references already exist for the following modified properties: 'members'.", status_code=400)
            self.au_members[m.group(1)].add(oid)
            return GraphResponse(204)
        m = re.match('/directory/administrativeUnits/([^/]+)/members/([^/]+)/\\$ref$', path)
        if m and method == 'DELETE':
            au_id, oid = m.groups()
            if oid not in self.au_members.get(au_id, set()):
                raise GraphError('not a member', status_code=404)
            self.au_members[au_id].remove(oid)
            return GraphResponse(204)
        m = re.match('/directory/administrativeUnits/([^/]+)$', path)
        if m and method == 'PATCH':
            self.admin_units[m.group(1)].update(json)
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
        m = re.match('/users/([^/]+)/assignLicense$', path)
        if m and method == 'POST':
            return self._assign_license(m.group(1), json)
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
        scope = body.get('directoryScopeId') or '/'
        if body['action'] == 'selfDeactivate':
            if scope == '/':
                self.active_roles.pop(body['roleDefinitionId'], None)
            else:
                self.scoped_active.pop((body['roleDefinitionId'], scope), None)
            return GraphResponse(201, {}, {'id': 'req2', 'status': 'Revoked'})
        if scope != '/':
            if (name, scope.rsplit('/', 1)[-1]) not in self.scoped_eligible:
                raise GraphPermissionError('403 not eligible', status_code=403, code='Authorization_RequestDenied')
            if not body.get('justification'):
                raise GraphError('The following policy rules failed: ["JustificationRule"]', status_code=400, code='RoleAssignmentRequestPolicyValidationFailed')
            self.scoped_active[(body['roleDefinitionId'], scope)] = name
            self._denied_after_activation = self.propagation
            return GraphResponse(201, {}, {'id': 'req1', 'status': 'Granted'})
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
