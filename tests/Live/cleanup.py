"""Deleting a role / an admin / a service removes its df-masking rows (event listeners + FKs)."""
import json, os, secrets, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from live import req, sysdb_value, refresh_tokens
refresh_tokens()
ok = []
def check(c, w):
    ok.append(bool(c)); print(('PASS ' if c else 'FAIL ') + w)
q = sysdb_value  # any system database type (DM_SYSDB / DM_SYSDB_DIALECT)
r = req('POST', 'system/role', body={'resource': [{'name': 'dm_tmp_role', 'is_active': True}]}); rid = r['json']['resource'][0]['id']
r = req('POST', 'system/admin', body={'resource': [{'email': 'dm-live-tmp@example.invalid', 'first_name': 'Tmp', 'last_name': 'Admin', 'name': 'Tmp Admin', 'password': 'Tmp-' + secrets.token_urlsafe(18), 'is_active': True}]}); aid = r['json']['resource'][0]['id']
acc = req('GET', 'system/data_masking/access')['json']
r = req('PATCH', 'system/data_masking/access', body={'admins': {'mode': acc['admins']['mode'], 'grants': [{'admin_id': g['admin_id']} for g in acc['admins']['grants']] + [{'admin_id': aid, 'duration': '1h'}]},
                                                     'roles': [{'role_id': rid, 'enabled': True, 'scope': 'except_restricted'}]})
check(r['status'] == 200, f'granted temp admin {aid} and enabled temp role {rid}')
check(q(f'SELECT COUNT(*) FROM dm_role_access WHERE role_id={rid}') == '1' and q(f'SELECT COUNT(*) FROM dm_admin_grant WHERE admin_id={aid}') == '1', 'rows exist')
r1 = req('DELETE', f'system/role/{rid}'); r2 = req('DELETE', f'system/admin/{aid}')
check(r1['status'] == 200 and r2['status'] == 200, 'role and admin deleted through the API')
check(q(f'SELECT COUNT(*) FROM dm_role_access WHERE role_id={rid}') == '0', 'dm_role_access row removed')
check(q(f'SELECT COUNT(*) FROM dm_admin_grant WHERE admin_id={aid}') == '0', 'dm_admin_grant row removed')
a = req('GET', 'system/data_masking/access')['json']
check(all(x['role_id'] != rid for x in a['roles']) and all(g['admin_id'] != aid for g in a['admins']['grants']), 'GET access no longer lists them')
print('ALL PASS' if all(ok) else 'SOME FAILED')
sys.exit(0 if all(ok) else 1)
