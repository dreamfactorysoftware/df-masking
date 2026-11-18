"""Existing instance: records, or diffs, a fixed set of API responses: status, headers and exact body bytes.

  python3 -I existing_instance.py record <out.json>      # before installing df-masking, then again after
  python3 -I existing_instance.py diff <before.json> <after.json> [--volatile <before2.json>]

Requests cover database services (list, single record, related, filters, order, fields, XML/CSV, schema, _spec,
writes, errors), an API-key app (role), anonymous, and system endpoints. Expects services crm (PostgreSQL),
store (PostgreSQL), crm_mysql (MySQL) and legacy (SQLite) as in README.md. Uses the same environment as lib/live.py
(DM_BASE_URL, DM_ADMIN_*, DM_API_KEY, DM_MYSQL). Bodies are stored base64 so the diff is byte-exact; the files contain
the instance's (synthetic) data, so keep them out of shared evidence (strip body_b64 first).
"""
import base64, hashlib, json, os, sys, urllib.parse, urllib.request, urllib.error
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from live import BASE, API_KEY, token, mysql  # noqa: E402

Q = urllib.parse.quote
VOLATILE_HEADERS = {'date', 'x-dreamfactory-trace-id'}


def tok():
    return token('admin')


def key():
    return API_KEY


def requests():
    A, K, N = 'admin', 'apikey', 'none'
    xml = {'Accept': 'application/xml'}
    csv = {'Accept': 'text/csv'}
    return [
        (A, 'GET', '', None, None),
        (A, 'GET', 'system/service?fields=id,name,label,type,is_active&order=id', None, None),
        (A, 'GET', 'system/role?related=role_service_access_by_role_id&fields=id,name,is_active', None, None),
        (A, 'GET', 'system/app?fields=id,name,role_id,api_key', None, None),
        (A, 'GET', 'system/admin?fields=id,email,name,is_sys_admin', None, None),
        (A, 'GET', 'system/environment', None, None),
        (A, 'GET', 'crm_mysql/_table/customers?limit=5', None, None),
        (A, 'GET', 'crm_mysql/_table/customers/1', None, None),
        (A, 'GET', 'crm_mysql/_table/customers?limit=3', None, xml),
        (A, 'GET', 'crm_mysql/_table/customers?limit=3', None, csv),
        (A, 'GET', 'crm_mysql/_table/customers?filter=' + Q("email like '%example%'") + '&order=' + Q('email desc') + '&fields=id,email,ssn&limit=5', None, None),
        (A, 'GET', 'crm_mysql/_table/customers?count_only=true&filter=' + Q("ssn like '3%'"), None, None),
        (A, 'GET', 'crm_mysql/_table/customers?fields=' + Q('gender,COUNT(*)') + '&group=gender', None, None),
        (A, 'GET', 'crm_mysql/_table/orders?limit=2&related=customers_by_customer_id', None, None),
        (A, 'GET', 'crm_mysql/_table/customers?ids=1,2&related=payment_methods_by_customer_id', None, None),
        (A, 'GET', 'crm_mysql/_table/customers?limit=3&as_list=true&id_field=email', None, None),
        (A, 'GET', 'crm_mysql/_schema/customers', None, None),
        (A, 'GET', 'crm_mysql/_spec?model=true', None, None),
        (A, 'PATCH', 'crm_mysql/_table/customers/5?fields=id,email,loyalty_tier', {'loyalty_tier': 'gold'}, None),
        (A, 'PATCH', 'crm_mysql/_table/customers/5?fields=id,email,loyalty_tier', {'loyalty_tier': 'gold'}, None),
        (A, 'POST', 'crm_mysql/_table/customers', {'resource': [{'first_name': 'Dup', 'last_name': 'Test', 'email': '__DUP__', 'created_at': '2026-10-29 00:00:00'}]}, None),
        (A, 'GET', 'crm_mysql/_table/nope', None, None),
        (A, 'GET', 'crm/_table/CustomerContacts?limit=5', None, None),
        (A, 'GET', 'crm/_table/patient_encounters?limit=5&order=1', None, None),
        (A, 'GET', 'store/_table/customers?limit=5', None, None),
        (A, 'GET', 'legacy/_table/legacy_users?limit=5', None, None),
        (A, 'GET', 'legacy/_table/legacy_users?limit=5', None, {'X-DreamFactory-Trace-Id': 'trace-12345678'}),
        (K, 'GET', 'crm_mysql/_table/customers?limit=5', None, None),
        (K, 'GET', 'crm_mysql/_table/customers/2', None, None),
        (K, 'GET', 'crm_mysql/_table/customers?limit=3', None, xml),
        (K, 'GET', 'crm_mysql/_table/customers?limit=3', None, csv),
        (K, 'GET', 'crm_mysql/_table/customers?filter=' + Q("ssn = '000-00-0000'") + '&fields=id', None, None),
        (K, 'GET', 'crm/_table/CustomerContacts?limit=5', None, None),
        (K, 'GET', 'crm/_table/CustomerContacts?limit=5', None, {'X-DreamFactory-Trace-Id': 'trace-12345678'}),
        (K, 'GET', 'legacy/_table/legacy_users?limit=5', None, None),
        (K, 'GET', 'store/_table/customers?limit=5', None, None),
        (K, 'PATCH', 'crm_mysql/_table/customers/5', {'loyalty_tier': 'gold'}, None),
        (N, 'GET', 'crm_mysql/_table/customers?limit=1', None, None),
    ]

def dup_email():
    return mysql('SELECT email FROM customers WHERE id=2')


def call(auth, method, path, body, headers):
    h = {'Accept': 'application/json'}
    if auth == 'admin':
        h['X-DreamFactory-Session-Token'] = tok()
    elif auth == 'apikey':
        h['X-DreamFactory-API-Key'] = key()
    if headers:
        h.update(headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode(); h['Content-Type'] = 'application/json'
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        resp = urllib.request.urlopen(r, timeout=120); status, rh, payload = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        status, rh, payload = e.code, e.headers, e.read()
    return status, [(k, v) for k, v in rh.items()], payload

def record(out):
    dup = dup_email()
    res = []
    for i, (auth, method, path, body, headers) in enumerate(requests()):
        if body is not None:
            body = json.loads(json.dumps(body).replace('__DUP__', dup))
        status, rh, payload = call(auth, method, path, body, headers)
        res.append({'n': i, 'auth': auth, 'method': method, 'path': path, 'req_headers': headers or {}, 'status': status,
                    'headers': rh, 'sha256': hashlib.sha256(payload).hexdigest(), 'len': len(payload),
                    'body_b64': base64.b64encode(payload).decode()})
    json.dump(res, open(out, 'w'), indent=1)
    print(f'recorded {len(res)} responses -> {out}')

def norm_headers(hs):
    return sorted((k.lower(), v) for k, v in hs if k.lower() not in VOLATILE_HEADERS)

def diff(a, b, volatile=None):
    A = json.load(open(a)); B = json.load(open(b)); V = json.load(open(volatile)) if volatile else None
    same = 0; diffs = []
    for i, (x, y) in enumerate(zip(A, B)):
        label = f"#{i:02d} {x['auth']:6} {x['method']:5} /{x['path'][:90]}" + (' ' + json.dumps(x['req_headers']) if x['req_headers'] else '')
        problems = []
        if x['status'] != y['status']:
            problems.append(f"status {x['status']} != {y['status']}")
        if x['sha256'] != y['sha256']:
            vol = V is not None and V[i]['sha256'] != x['sha256']
            problems.append('body differs' + (' (also differs between two runs BEFORE install: volatile)' if vol else ''))
        hx, hy = norm_headers(x['headers']), norm_headers(y['headers'])
        if hx != hy:
            problems.append('headers differ: ' + json.dumps(sorted(set(hx) ^ set(hy))))
        if problems:
            diffs.append((label, problems, x, y))
        else:
            same += 1
        print(('SAME  ' if not problems else 'DIFF  ') + label + (f"  [{x['status']}, {x['len']} bytes, sha256 {x['sha256'][:12]}]" if not problems else '  ' + '; '.join(problems)))
    print(f'\n{same}/{len(A)} byte-identical (status + body + headers except Date and X-DreamFactory-Trace-Id)')
    return diffs

if __name__ == '__main__':
    if sys.argv[1] == 'record':
        record(sys.argv[2])
    else:
        vol = sys.argv[sys.argv.index('--volatile') + 1] if '--volatile' in sys.argv else None
        d = diff(sys.argv[2], sys.argv[3], vol)
        for label, problems, x, y in d:
            if any('body differs' in p for p in problems):
                bx = base64.b64decode(x['body_b64']).decode('utf-8', 'replace'); by = base64.b64decode(y['body_b64']).decode('utf-8', 'replace')
                import difflib
                print('\n--- ' + label)
                for line in list(difflib.unified_diff(bx[:4000].replace(',', ',\n').splitlines(), by[:4000].replace(',', ',\n').splitlines(), lineterm='', n=1))[:30]:
                    print('   ' + line[:200])
