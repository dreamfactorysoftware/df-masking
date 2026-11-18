"""Every baseline evaluates without errors; Apply hipaa and pci_dss change exactly what
`changes` listed (verified against the real settings before/after, not against Apply's own response);
reports JSON/CSV contain no data values. Restores access, formats, mode, rules and adoptions at the end."""
import csv, io, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from live import req, refresh_tokens, mysql, role_id, admin_id, ADMIN2, EVID
OUT = EVID + '/'
refresh_tokens()
results = []
def check(ok, what):
    results.append(bool(ok)); print(('PASS ' if ok else 'FAIL ') + what); return ok
def get(p):
    r = req('GET', p); assert r['status'] == 200, (p, r['status'], r['text'][:300]); return r['json']

def state():
    a = get('system/data_masking/access')
    return {
        'mode': get('system/data_masking')['mode'],
        'ai': a['ai'], 'admins_mode': a['admins']['mode'],
        'grants': {g['admin_id']: g['expires_at'] for g in a['admins']['grants']},
        'roles': {x['role_id']: (x['enabled'], x['scope']) for x in a['roles']},
        'formats': {m['class']: m['format'] for m in get('system/data_masking/mask')['resource']},
        'rules': {r['id']: (r['match'], r['pattern'], r['class']) for r in get('system/data_masking/rule')['resource']},
    }

def derive(s0, s1):
    ids = set()
    for k in ('mode', 'ai', 'admins_mode'):
        if s0[k] != s1[k]:
            ids.add(k)
    for aid in set(s0['grants']) | set(s1['grants']):
        if s0['grants'].get(aid) != s1['grants'].get(aid):
            ids.add(f'grant:{aid}')
    for rid in set(s0['roles']) | set(s1['roles']):
        if s0['roles'].get(rid) != s1['roles'].get(rid):
            ids.add(f'role:{rid}')
    for c in set(s0['formats']) | set(s1['formats']):
        if s0['formats'].get(c) != s1['formats'].get(c):
            ids.add(f'format:{c}')
    new_rules = [s1['rules'][i] for i in s1['rules'] if i not in s0['rules']]
    gone = [i for i in s0['rules'] if i not in s1['rules']]
    return ids, new_rules, gone

orig = state()
orig_adopted = [b['id'] for b in get('system/security_baseline')['resource'] if b['adopted']]
try:
    # 1. every baseline evaluates
    lst = get('system/security_baseline')['resource']
    check(sorted(b['id'] for b in lst) == sorted(['hipaa', 'pci_dss', 'glba', 'cjis', 'gdpr', 'soc2', 'iso27001']), '7 baselines listed')
    for b in lst:
        d = get('system/security_baseline/' + b['id'])
        statuses = [c['status'] for c in d['controls']]
        bad = [c['id'] for c in d['controls'] if c['status'] not in ('pass', 'fail', 'manual', 'na')]
        errs = [c['id'] for c in d['controls'] if 'could not be checked' in (c.get('detail') or '').lower()]
        norefs = [c['id'] for c in d['controls'] if not c['refs']]
        score = d['score']
        check(not bad and not errs and not norefs and score['pass'] == statuses.count('pass') and score['fail'] == statuses.count('fail'),
              f"{b['id']:9} {len(statuses)} controls evaluate: pass {statuses.count('pass')}, fail {statuses.count('fail')}, manual {statuses.count('manual')}, na {statuses.count('na')}; errors {errs}; missing refs {norefs}")
    # 2. loosen everything Apply owns
    r = req('PATCH', 'system/data_masking/access', body={'admins': {'mode': 'all', 'grants': [{'admin_id': admin_id(ADMIN2[0]), 'duration': 'forever'}]},
                                                         'ai': 'same_as_admins', 'roles': [{'role_id': role_id(), 'enabled': True, 'scope': 'all'}]})
    check(r['status'] == 200, 'loosened access (admins all, Priya forever, ai same_as_admins, role support scope all)')
    r = req('PATCH', 'system/data_masking/mask', body={'resource': [{'class': 'date_of_birth', 'format': 'token'}]})
    check(r['status'] == 200, 'loosened date_of_birth format to token')
    for bid, body in (('hipaa', {}), ('pci_dss', {'mode': 'on'})):
        planned = get('system/security_baseline/' + bid + ('?mode=on' if body.get('mode') else ''))['changes']
        s0 = state()
        r = req('POST', f'system/security_baseline/{bid}/apply', body=body)
        check(r['status'] == 200 and r['json']['adopted'], f'{bid}: apply {json.dumps(body)} -> 200, adopted')
        s1 = state()
        ids, new_rules, gone = derive(s0, s1)
        planned_ids = {c['id'] for c in planned}
        planned_rules = sorted(i for i in planned_ids if i.startswith('rule:'))
        planned_other = {i for i in planned_ids if not i.startswith('rule:')}
        print(f'   planned changes: {[c["id"] for c in planned]}')
        print(f'   observed setting changes: {sorted(ids)}; new rules {len(new_rules)}; rules removed {len(gone)}')
        check(planned_other == ids, f'{bid}: settings that changed == settings `changes` listed')
        check(len(new_rules) == len(planned_rules) and not gone, f'{bid}: {len(new_rules)} rules added == {len(planned_rules)} rule changes listed; none removed')
        check(sorted(c['id'] for c in r['json'].get('applied', [])) == sorted(planned_ids) and
              [c['text'] for c in r['json'].get('applied', [])] == [c['text'] for c in planned], f'{bid}: Apply reported exactly the planned changes (ids and texts)')
        after = get('system/security_baseline/' + bid + ('?mode=on' if body.get('mode') else ''))
        check(after['changes'] == [], f'{bid}: nothing left to change after Apply')
        r2 = req('POST', f'system/security_baseline/{bid}/apply', body=body)
        check(r2['status'] == 200 and r2['json'].get('applied') == [] and state() == s1, f'{bid}: second Apply changes nothing')
        # strictest wins / add-only spot checks
        if bid == 'hipaa':
            check(s1['ai'] == 'masked' and s1['admins_mode'] == 'selected' and s1['roles'][role_id()] == (True, 'except_restricted') and s1['formats']['date_of_birth'] in ('year', 'redact', 'null'),
                  'hipaa: ai masked, admins selected, role except_restricted, date_of_birth year/redact/null')
            check(s1['grants'].get(admin_id(ADMIN2[0])) is not None, 'hipaa: Priya grant capped (expires_at set), not removed: ' + str(s1['grants'].get(admin_id(ADMIN2[0]))))
        if bid == 'pci_dss':
            check(s1['mode'] == 'on', 'pci_dss with mode on: masking mode On')
        json.dump({'planned': planned, 'applied': r['json'].get('applied'), 'observed': sorted(ids), 'new_rules': new_rules}, open(OUT + f'17-apply-{bid}.json', 'w'), indent=1)
    # 3. reports contain no values
    values = set()
    for sql, db in (("SELECT email, ssn, phone, first_name, last_name, street_address, notes, last_login_ip FROM customers", 'crm_mysql'),
                    ("SELECT card_number, iban, cvv FROM payment_methods", 'crm_mysql')):
        for line in mysql(sql, db=db).splitlines():
            values.update(v for v in line.split('\t') if v and v != 'NULL' and len(v) >= 5)
    # DreamFactory user names (the report's access summary lists admins by name) are not data values.
    users = set()
    for kind in ('admin', 'user'):  # through the API: works with any system database
        for u in req('GET', f'system/{kind}?fields=first_name,last_name,name,email')['json'].get('resource', []):
            for v in (u.get('first_name'), u.get('last_name'), u.get('name'), u.get('email')):
                users.update(w for w in str(v or '').replace('@', ' ').split() if w)
    allow = sorted(v for v in values if v in users)
    values -= set(allow)
    print(f'   {len(values)} distinct raw values (len >= 5) loaded for the report value check (excluded as DreamFactory user names: {allow})')
    for bid in ('hipaa', 'pci_dss'):
        rj = req('GET', f'system/security_baseline/{bid}/report?format=json')
        rc = req('GET', f'system/security_baseline/{bid}/report?format=csv', headers={'Accept': 'text/csv'}, raw=True)
        open(OUT + f'17-report-{bid}.json', 'w').write(rj['text']); open(OUT + f'17-report-{bid}.csv', 'w').write(rc['text'])
        found = [v for v in values if v in rj['text'] or v in rc['text']]
        j = rj['json']
        rows = list(csv.reader(io.StringIO(rc['text'])))
        check(rj['status'] == 200 and rc['status'] == 200 and not found,
              f"{bid}: report JSON ({len(rj['text'])} B, keys {sorted(j.keys())}) and CSV ({len(rows) - 1} rows) contain none of the raw values (found: {len(found)})")
        check(len(rows) - 1 == len(j['controls']), f'{bid}: CSV has one row per control ({len(j["controls"])})')
finally:
    # restore
    req('PATCH', 'system/data_masking/access', body={'admins': {'mode': orig['admins_mode'], 'grants': [{'admin_id': a} for a in orig['grants']]},
                                                     'ai': orig['ai'], 'roles': [{'role_id': rid, 'enabled': e, 'scope': s} for rid, (e, s) in orig['roles'].items()]})
    req('PATCH', 'system/data_masking/mask', body={'resource': [{'class': c, 'format': f} for c, f in orig['formats'].items()]})
    for rid in [i for i in state()['rules'] if i not in orig['rules']]:
        req('DELETE', f'system/data_masking/rule/{rid}')
    for bid in [b['id'] for b in get('system/security_baseline')['resource'] if b['adopted'] and b['id'] not in orig_adopted]:
        req('DELETE', f'system/security_baseline/{bid}')
    req('PATCH', 'system/data_masking', body={'mode': orig['mode']})
    now = state()
    print('restored:', 'OK' if now == orig else 'DIFFERS ' + json.dumps({k: (orig[k], now[k]) for k in orig if orig[k] != now[k]}, default=str)[:500])
print('ALL PASS' if all(results) else 'SOME FAILED')
sys.exit(0 if all(results) else 1)
