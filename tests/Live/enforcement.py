"""Enforcement live checks. Run: python3 -I tests/Live/enforcement.py <name>... | all  (see README.md)"""
import sys
import urllib.parse

import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from live import *  # noqa

Q = urllib.parse.quote


def real_customer(cid=1):
    line = mysql(f"SELECT email, ssn, phone, first_name FROM customers WHERE id={cid}")
    email, ssn, phone, first = line.split('\t')
    return {'email': email, 'ssn': ssn, 'phone': phone, 'first_name': first}


def check_formats():
    e = Evidence('01-formats-json-xml-csv')
    real = real_customer(1)
    e.note(f"Role user = app mobile-app (role support) via API key. Mode on. Raw values of customer 1 are read from MySQL directly and must not appear.")
    with ModeOn():
        r = req('GET', 'crm_mysql/_table/customers?limit=3', auth='apikey')
        e.show(r, title='JSON list')
        rec = rows(r)[0]
        e.check(r['status'] == 200 and {'email', 'ssn'} <= listed(r, 'X-DreamFactory-Masked-Fields'), 'JSON 200, X-DreamFactory-Masked-Fields lists email and ssn')
        e.check(rec['email'].startswith('EMAIL_') and len(rec['email']) == 14, 'email -> EMAIL_<8 hex> token')
        e.check(rec['ssn'] == G * 8 or rec['ssn'].endswith(real['ssn'][-4:]) and G in rec['ssn'], 'ssn masked (restricted: redact/last4)')
        e.check(rec['phone'].startswith('PHONE_'), 'phone -> PHONE_ token')
        e.check(G in rec['date_of_birth'] and rec['date_of_birth'][:4].isdigit(), 'date_of_birth -> year format')
        e.check(rec['state'] == 'IL' or G not in str(rec.get('state')), 'clear column untouched')
        for k in ('email', 'ssn', 'phone'):
            e.check(real[k] not in r['text'], f'raw {k} absent from JSON')
        rx = req('GET', 'crm_mysql/_table/customers?limit=3', auth='apikey', headers={'Accept': 'application/xml'}, raw=True)
        e.show(rx, title='XML (Accept: application/xml)', trim=700)
        e.check(rx['status'] == 200 and 'xml' in rx['headers'].get('Content-Type', ''), 'XML response')
        e.check('EMAIL_' in rx['text'] and all(real[k] not in rx['text'] for k in ('email', 'ssn', 'phone')), 'XML masked, no raw values')
        rc = req('GET', 'crm_mysql/_table/customers?limit=3', auth='apikey', headers={'Accept': 'text/csv'}, raw=True)
        e.show(rc, title='CSV (Accept: text/csv)', trim=700)
        e.check(rc['status'] == 200 and 'csv' in rc['headers'].get('Content-Type', ''), 'CSV response')
        e.check('EMAIL_' in rc['text'] and all(real[k] not in rc['text'] for k in ('email', 'ssn', 'phone')), 'CSV masked, no raw values')
        rf = req('GET', 'crm_mysql/_table/customers?limit=2&file=customers.csv', auth='apikey', raw=True)
        e.check(rf['status'] == 200 and 'EMAIL_' in rf['text'] and real['email'] not in rf['text'], '?file=customers.csv download masked')
    return e.save()


def check_single_related():
    e = Evidence('02-single-record-and-related')
    real = real_customer(1)
    card = mysql("SELECT card_number FROM payment_methods WHERE customer_id=1 LIMIT 1")
    with ModeOn():
        r = req('GET', 'crm_mysql/_table/customers/1', auth='apikey')
        e.show(r, title='single record by id')
        e.check(r['status'] == 200 and r['json']['email'].startswith('EMAIL_') and real['email'] not in r['text'], 'single record masked')
        r = req('GET', 'crm_mysql/_table/orders?limit=2&related=customers_by_customer_id', auth='apikey')
        e.show(r, title='belongs_to related', trim=1200)
        rel = rows(r)[0].get('customers_by_customer_id')
        e.check(isinstance(rel, dict) and rel.get('email', '').startswith('EMAIL_'), 'belongs_to related record masked')
        r = req('GET', 'crm_mysql/_table/customers?ids=1&related=payment_methods_by_customer_id,orders_by_customer_id', auth='apikey')
        e.show(r, title='has_many related', trim=1500)
        pms = rows(r)[0].get('payment_methods_by_customer_id') or []
        e.check(len(pms) > 0, 'has_many related present')
        if pms:
            e.check(G in str(pms[0].get('card_number')) and card not in r['text'], 'related payment card masked, raw card absent')
            e.check(pms[0].get('cvv') in (None, G * 8), 'related cvv masked')
        r = req('GET', 'crm_mysql/_table/customers?limit=2&as_list=true&id_field=email', auth='apikey')
        e.show(r, title='as_list with id_field=email')
        e.check(all(str(x).startswith('EMAIL_') for x in rows(r)), 'as_list values masked')
    return e.save()


def check_filters():
    e = Evidence('03-filter-order-group-fields')
    real = real_customer(1)
    total = int(mysql("SELECT COUNT(*) FROM customers"))
    e.note(f'customers rows in MySQL: {total}')
    with ModeOn():
        def get(params, title):
            r = req('GET', 'crm_mysql/_table/customers?' + params, auth='apikey')
            e.show(r, title=title, trim=500)
            return r
        r = get('filter=' + Q(f"email = '{real['email']}'") + '&fields=id', 'identity equality: allowed')
        e.check(rows(r) == [{'id': 1}] and 'X-DreamFactory-Masking-Rewrites' not in r['headers'], 'email = exact match returns 1 row, nothing dropped')
        # A comparison the caller may not make is UNKNOWN (SQL NULL logic): it matches
        # no rows, never widens, and the answer never depends on the masked value.
        r = get('filter=' + Q("email like '%example.net'") + '&fields=id&include_count=true&limit=1', 'identity LIKE: unknown -> no rows')
        e.check(r['headers'].get('X-DreamFactory-Masking-Rewrites') == 'filter:email', 'Rewrites: filter:email (conditions on email matched no rows)')
        e.check(r['json']['meta']['count'] == 0 and rows(r) == [], 'LIKE on a masked column matches no rows (count 0), never widened')
        r = get('filter=' + Q(f"ssn = '{real['ssn']}'") + '&count_only=true', 'restricted equality (real value): no rows (count_only)')
        r2 = get('filter=' + Q("ssn = '000-00-0000'") + '&count_only=true', 'restricted equality (wrong value): no rows (count_only)')
        e.check(r['json'] == 0 and r2['json'] == 0 and r['headers'].get('X-DreamFactory-Masking-Rewrites') == 'filter:ssn' == r2['headers'].get('X-DreamFactory-Masking-Rewrites'), 'count_only gives the same answer for a real and a wrong SSN (both 0)')
        r = get('filter=' + Q('ssn IS NULL') + '&count_only=true', 'IS NULL on restricted: allowed')
        nulls = int(mysql('SELECT COUNT(*) FROM customers WHERE ssn IS NULL'))
        e.check(r['json'] == nulls and 'X-DreamFactory-Masking-Rewrites' not in r['headers'], 'IS NULL allowed')
        in26 = ','.join(f"'x{i}@example.com'" for i in range(26))
        r = get('filter=' + Q(f'email IN ({in26})') + '&count_only=true', 'IN with 26 values: unknown -> no rows')
        e.check(r['json'] == 0 and r['headers'].get('X-DreamFactory-Masking-Rewrites') == 'filter:email', 'IN > 25 matches no rows')
        il = int(mysql("SELECT COUNT(*) FROM customers WHERE state='IL'"))
        r = get('filter=' + Q("(state = 'IL') OR (ssn like '3%')") + '&count_only=true', 'OR with an unknown term: the clear side stays')
        e.check(r['json'] == il and r['headers'].get('X-DreamFactory-Masking-Rewrites') == 'filter:ssn', f'OR keeps only (state = IL): {il} rows')
        r = get('filter=' + Q("(state = 'IL') AND (ssn like '3%')") + '&count_only=true', 'AND with an unknown term: no rows')
        e.check(r['json'] == 0, 'AND with an unknown term matches no rows')
        r = get('filter=' + Q("NOT (ssn = '000-00-0000')") + '&count_only=true', 'NOT of an unknown term: no rows')
        e.check(r['json'] == 0 and r['headers'].get('X-DreamFactory-Masking-Rewrites') == 'filter:ssn', 'NOT (unknown) matches no rows')
        r = get('order=' + Q('email desc,id') + '&fields=id&limit=3', 'order on masked column: dropped')
        e.check(r['headers'].get('X-DreamFactory-Masking-Rewrites') == 'order:email' and [x['id'] for x in rows(r)] == [1, 2, 3], 'order:email dropped, id order kept')
        r = get('fields=' + Q('gender,COUNT(*)') + '&group=gender', 'group on masked column: dropped')
        e.check(r['status'] == 200 and 'group:gender' in r['headers'].get('X-DreamFactory-Masking-Rewrites', ''), 'group:gender dropped, query still succeeds')
        r = get('fields=' + Q('MIN(ssn),MAX(email),COUNT(ssn)'), 'aggregates on masked columns: dropped except COUNT')
        drop = r['headers'].get('X-DreamFactory-Masking-Rewrites', '')
        e.check('fields:ssn' in drop and 'fields:email' in drop and real['ssn'] not in r['text'] and real['email'] not in r['text'], 'MIN/MAX dropped, COUNT allowed')
        r = get('filter=' + Q("first_name = ') OR (ssn LIKE ''3%'''") + '&count_only=true', 'ambiguous filter mentioning a masked column: no rows')
        e.check(r['headers'].get('X-DreamFactory-Masking-Rewrites') == 'filter:*' and r['json'] == 0, 'filter:* (could not be checked) matches no rows')
        r = get('filter=' + Q("loyalty_tier = 'gold'") + '&count_only=true', 'filter on clear column: untouched')
        e.check(r['json'] == int(mysql("SELECT COUNT(*) FROM customers WHERE loyalty_tier='gold'")) and 'X-DreamFactory-Masking-Rewrites' not in r['headers'], 'clear filter untouched')
        # POST-tunneled GET with the filter in the body
        r = req('POST', 'crm_mysql/_table/customers?count_only=true', auth='apikey', body={'filter': "ssn like '3%'"}, headers={'X-HTTP-Method': 'GET'})
        e.show(r, title='POST with X-HTTP-Method: GET, filter in the body')
        e.check(r['json'] == 0 and r['headers'].get('X-DreamFactory-Masking-Rewrites') == 'filter:ssn', 'body filter matches no rows too')
    return e.save()


def check_writes():
    e = Evidence('04-write-back-expressions-write-filters')
    real = real_customer(5)
    before = mysql('SELECT email, ssn, phone, first_name, loyalty_tier FROM customers WHERE id=5')
    e.note(f'Caller: {ADMIN[0]} (admins are masked by default; admins mode none). DB checked directly in MySQL.')
    with ModeOn():
        r = req('GET', 'crm_mysql/_table/customers/5')
        e.show(r, title='admin reads customer 5: masked')
        rec = r['json']
        e.check(rec['email'].startswith('EMAIL_'), 'admin masked by default')
        tier = rec['loyalty_tier']
        new_tier = 'silver' if tier != 'silver' else 'gold'
        rec2 = dict(rec)
        rec2['loyalty_tier'] = new_tier
        r = req('PUT', 'crm_mysql/_table/customers/5', body=rec2)
        e.show(r, title='PUT the masked record back with one real change (loyalty_tier)')
        after = mysql('SELECT email, ssn, phone, first_name, loyalty_tier FROM customers WHERE id=5')
        e.check(r['status'] == 200, 'PUT 200')
        e.check(after.split('\t')[:4] == before.split('\t')[:4], 'masked values were NOT written (email/ssn/phone/first_name unchanged in MySQL)')
        e.check(after.split('\t')[4] == new_tier, 'the real change (loyalty_tier) was written')
        r = req('PATCH', 'crm_mysql/_table/customers/5', body={'loyalty_tier': tier})
        e.check(r['status'] == 200 and mysql('SELECT loyalty_tier FROM customers WHERE id=5') == tier, 'restored loyalty_tier')
        r = req('PATCH', 'crm_mysql/_table/customers/5', body={'ssn': rec['ssn']})
        e.show(r, title='PATCH sending only a masked value back')
        e.check(r['status'] == 400 and mysql('SELECT ssn FROM customers WHERE id=5') == real['ssn'], '400 "Nothing to write", ssn unchanged')
        r = req('PATCH', 'crm_mysql/_table/customers/5', body={'notes': {'expression': 'ssn'}})
        e.show(r, title='PATCH with an expression')
        e.check(r['status'] == 400 and 'Expressions are not allowed on tables with masked columns' in r['text'], '400 expressions not allowed')
        r = req('PATCH', 'crm_mysql/_table/customers?filter=' + Q("email like '%example%'"), body={'resource': [{'loyalty_tier': 'gold'}]})
        e.show(r, title='PATCH filtered with LIKE on a masked column')
        e.check(r['status'] == 400, 'LIKE in a write filter on a masked column -> 400')
        r = req('PATCH', 'crm_mysql/_table/customers?filter=' + Q(f"ssn = '{real['ssn']}'"), body={'resource': [{'loyalty_tier': tier}]})
        e.check(r['status'] == 400, 'restricted equality in a write filter -> 400')
        r = req('PATCH', 'crm_mysql/_table/customers?filter=' + Q(f"email = '{real['email']}'"), body={'resource': [{'loyalty_tier': tier}]})
        e.show(r, title='PATCH filtered with equality on an identity column (allowed)')
        e.check(r['status'] == 200 and len(rows(r)) == 1, 'identity equality in a write filter allowed')
        e.check(real['email'] not in r['text'], 'write response masked')
        e.check(mysql('SELECT email, ssn, phone, first_name, loyalty_tier FROM customers WHERE id=5') == before, 'row 5 identical to before')
    return e.save()


def check_errors():
    e = Evidence('05-error-scrubbing')
    dup = mysql('SELECT email FROM customers WHERE id=2')
    with ModeOn():
        r = req('POST', 'crm_mysql/_table/customers', body={'resource': [{'first_name': 'Dup', 'last_name': 'Test', 'email': dup, 'created_at': '2026-10-29 00:00:00'}]})
        e.show(r, title='POST a customer with an existing (UNIQUE) email', trim=1500)
        e.check(r['status'] >= 400, 'unique violation -> error')
        e.check(dup not in r['text'], 'error does not echo the submitted email')
        # Integrity errors (SQLSTATE class 23) are reduced to a fixed message that keeps
        # only the operation and the SQLSTATE.
        e.check('Database error during insert (SQLSTATE 23000). Data Masking removed the details.' in r['text'],
                'reduced to the fixed message (operation + SQLSTATE)')
    e.note('\nSame request with masking preview (no scrubbing in preview: values unchanged by design) is not repeated here.')
    return e.save()


SCRIPT_NAME = 'crm_mysql._table.customers.get.post_process'
SCRIPT_CRM = 'crm._table.CustomerContacts.get.post_process'
SCRIPT_BODY = r"""
$content = $event['response']['content'];
$first = isset($content['resource'][0]) ? $content['resource'][0] : $content;
$seen = [];
foreach (['email', 'EMail', 'ssn', 'phone'] as $k) { if (isset($first[$k])) { $seen[$k] = $first[$k]; } }
if (isset($content['resource'][0])) { $event['response']['content']['resource'][0]['script_saw'] = $seen; }
else { $event['response']['content']['script_saw'] = $seen; }
"""


def check_script():
    e = Evidence('06-event-script-sees-masked')
    real = real_customer(1)
    e.note('PHP post_process event scripts with allow_event_modification copy what they see into a new key "script_saw".')
    e.note('If a script saw raw values, "script_saw" (not a masked column) would carry them to the client.')
    created = []
    try:
        for name in (SCRIPT_NAME, SCRIPT_CRM):
            r = req('POST', 'system/event_script/' + name, body={'name': name, 'type': 'php', 'content': SCRIPT_BODY, 'is_active': True, 'allow_event_modification': True})
            e.check(r['status'] in (200, 201), f'created event script {name}')
            created.append(name)
        with ModeOn():
            r = req('GET', 'crm_mysql/_table/customers?limit=1', auth='apikey')
            e.show(r, title='crm_mysql customers (script on the specific table event)')
            saw = rows(r)[0].get('script_saw', {})
            e.check(saw.get('email', '').startswith('EMAIL_') and real['email'] not in r['text'], 'script received the masked email')
            e.check(saw.get('ssn') in (G * 8,) or G in str(saw.get('ssn')), 'script received the masked ssn')
            r = req('GET', 'crm/_table/CustomerContacts?limit=1', auth='apikey')
            e.show(r, title='crm CustomerContacts (pgsql)')
            saw = rows(r)[0].get('script_saw', {})
            e.check(r['status'] == 200 and saw, 'crm script ran')
            e.check(all(masked(v) for v in saw.values()), 'crm script saw only masked values: ' + json.dumps(saw))
    finally:
        for name in created:
            req('DELETE', 'system/event_script/' + name)
    return e.save()


PROBE = 'enf_probe'
PROBE_BODY = r"""
$get = $platform['api']->get;
return $get('crm_mysql/_table/customers?limit=1&fields=id,email,ssn');
"""


def check_platform_api():
    e = Evidence('07-script-platform-api')
    real = real_customer(1)
    sid = None
    try:
        r = req('POST', 'system/service', body={'resource': [{'name': PROBE, 'label': 'Enforcement probe', 'type': 'php', 'is_active': True, 'config': {'content': PROBE_BODY}}]})
        e.show(r, title='create a PHP script service that calls platform.api')
        sid = rows(r)[0]['id'] if r['status'] in (200, 201) else None
        e.check(sid is not None, 'script service created')
        with ModeOn():
            r = req('GET', PROBE)
            e.show(r, title='admin calls the script service (internal platform.api call)')
            e.check(r['status'] == 200 and 'EMAIL_' in r['text'] and real['email'] not in r['text'] and real['ssn'] not in r['text'], 'platform.api result masked')
    finally:
        if sid:
            req('DELETE', f'system/service/{sid}')
    return e.save()


def check_spec():
    e = Evidence('08-spec-model')
    real = real_customer(1)
    with ModeOn():
        r = req('GET', 'crm_mysql/_spec?model=true')
        e.show(r, title='GET crm_mysql/_spec?model=true (admin, masked by default)', trim=1500)
        m = r['json'] or {}
        c = (m.get('tables') or {}).get('customers', {})
        e.check(r['status'] == 200 and c, 'model returned')
        samples = c.get('sample_data') or []
        e.check(samples and all(str(s.get('email', '')).startswith('EMAIL_') for s in samples), 'sample_data emails masked')
        e.check(real['email'] not in r['text'] and real['ssn'] not in r['text'], 'no raw sample values')
        e.check('gender' not in (c.get('enum_values') or {}), 'enum_values of masked gender removed')
        e.check('masked_columns' in c, 'masked_columns listed for the AI')
        e.check(r['headers'].get('X-DreamFactory-Masked-Fields') == '*', 'X-DreamFactory-Masked-Fields: *')
        r2 = req('GET', 'crm_mysql/_spec')
        e.check(r2['status'] == 200 and 'openapi' in r2['text'][:200], 'plain _spec untouched (no data)')
    r = req('GET', 'crm_mysql/_spec?model=true')
    e.show(r, title='same in preview mode: untouched', trim=300)
    return e.save()


def check_preview():
    e = Evidence('09-preview')
    real = real_customer(1)
    prev = mode()
    try:
        if prev != 'preview':
            set_mode('preview')
        before = sysdb_value("SELECT COUNT(*) FROM dm_activity WHERE kind='preview'")
        r1 = req('GET', 'crm_mysql/_table/payment_methods?limit=2', auth='apikey')
        r2 = req('GET', 'crm_mysql/_table/payment_methods?limit=2', auth='apikey')
        e.show(r1, title='preview: values unchanged, no masking headers')
        e.check(masking_headers(r1) == {}, 'no masking headers in Preview')
        e.check(G not in r1['text'] and 'EMAIL_' not in r1['text'], 'values unchanged')
        e.check(r1['text'] == r2['text'], 'repeatable')
        after = sysdb_value("SELECT COUNT(*) FROM dm_activity WHERE kind='preview'")
        last = sysdb(top(1, 'actor, text, target, meta', "FROM dm_activity WHERE kind='preview' ORDER BY id DESC"))
        e.note('latest preview activity: ' + json.dumps(last))
        e.check(int(after) - int(before) <= 1, f'throttled: {int(after) - int(before)} new preview row(s) for 2 requests')
        e.check(any('card_number' in str(x) for x in sum(last, [])), 'the would-mask row names card_number')
    finally:
        if mode() != prev:
            set_mode(prev)
    return e.save()


def check_access_ai():
    e = Evidence('10-admin-grant-ai-role-access')
    real = real_customer(1)
    original = access()
    e.note('original access: ' + json.dumps(original)[:600])
    try:
        with ModeOn():
            r = req('GET', 'crm_mysql/_table/customers/1')
            e.check(r['json']['email'].startswith('EMAIL_'), 'admin masked by default')
            set_access({'admins': {'mode': 'selected', 'grants': [{'admin_id': admin_id(), 'duration': '1h'}]}})
            r = req('GET', 'crm_mysql/_table/customers/1')
            e.show(r, title='admin with a 1h grant: real values')
            e.check(r['json']['email'] == real['email'], 'granted admin sees the real email')
            e.check(masking_headers(r) == {}, 'no masking header for a privileged caller')
            r = req('GET', 'crm_mysql/_table/customers/1', headers={'X-DreamFactory-Trace-Id': 'enf-ai-trace-0001'})
            e.show(r, title='same admin through an AI session (X-DreamFactory-Trace-Id): masked')
            e.check(r['json']['email'].startswith('EMAIL_'), 'AI session masked although the admin has a grant')
            set_access({'ai': 'same_as_admins'})
            r = req('GET', 'crm_mysql/_table/customers/1', headers={'X-DreamFactory-Trace-Id': 'enf-ai-trace-0002'})
            e.show(r, title='ai = same_as_admins: the AI session gets what the admin gets')
            e.check(r['json']['email'] == real['email'], 'AI real values with ai=same_as_admins')
            set_access({'ai': 'masked', 'admins': {'mode': 'selected', 'grants': [{'admin_id': admin_id(), 'duration': '1h'}]}})
            # expiry: move the grant into the past directly (time travel), caches expire within 30 s / version bump
            sysdb(f"UPDATE dm_admin_grant SET expires_at = '{utc_ago(60)}' WHERE admin_id={admin_id()}")
            set_access({'ai': 'masked'})  # any write bumps the policy version
            r = req('GET', 'crm_mysql/_table/customers/1')
            e.check(r['json']['email'].startswith('EMAIL_'), 'expired grant -> masked again')
            # role access
            set_access({'roles': [{'role_id': role_id(), 'enabled': True, 'scope': 'except_restricted'}]})
            r = req('GET', 'crm_mysql/_table/customers/1', auth='apikey')
            e.show(r, title='role support granted real values except restricted')
            e.check(r['json']['email'] == real['email'] and real['ssn'] not in r['text'], 'identity real, restricted (ssn) masked')
            r = req('GET', 'crm_mysql/_table/customers/1', auth='apikey', headers={'X-DreamFactory-Trace-Id': 'enf-ai-trace-0003'})
            e.check(r['json']['email'].startswith('EMAIL_'), 'same role through an AI session: masked (ai=masked)')
            set_access({'roles': [{'role_id': role_id(), 'enabled': True, 'scope': 'all'}]})
            r = req('GET', 'crm_mysql/_table/customers/1', auth='apikey')
            e.check(r['json']['ssn'] == real['ssn'], 'scope all: restricted real too')
    finally:
        restore = {'admins': {'mode': original['admins']['mode'], 'grants': [{'admin_id': g['admin_id']} for g in original['admins']['grants']]},
                   'ai': original['ai'], 'roles': [{'role_id': x['role_id'], 'enabled': x['enabled'], 'scope': x['scope']} for x in original['roles']]}
        try:
            set_access(restore)
        except AssertionError as ex:
            e.note('restore failed: ' + str(ex))
        e.note('restored access: ' + json.dumps(access())[:600])
    return e.save()


def check_ai_settings():
    e = Evidence('11-ai-cannot-change-settings')
    before = sysdb_value("SELECT COUNT(*) FROM dm_activity WHERE kind='blocked'")
    m = mode()
    r = req('PATCH', 'system/data_masking', body={'mode': 'off'}, headers={'X-DreamFactory-Trace-Id': 'enf-ai-trace-0100'})
    e.show(r, title='AI session tries to turn masking off')
    e.check(r['status'] == 403 and mode() == m, '403 and mode unchanged')
    r = req('PATCH', 'system/data_masking/access', body={'ai': 'same_as_admins'}, headers={'X-DreamFactory-Trace-Id': 'enf-ai-trace-0101'})
    e.show(r, title='AI session tries to loosen AI access')
    e.check(r['status'] == 403 and access()['ai'] == 'masked', '403 and ai unchanged')
    r = req('POST', 'system/security_baseline/hipaa/apply', body={}, headers={'X-DreamFactory-Trace-Id': 'enf-ai-trace-0102'})
    e.show(r, title='AI session tries to apply a baseline')
    e.check(r['status'] == 403, '403 on baselines')
    r = req('GET', 'system/data_masking', headers={'X-DreamFactory-Trace-Id': 'enf-ai-trace-0103'})
    e.check(r['status'] == 200, 'AI may read the overview')
    after = sysdb_value("SELECT COUNT(*) FROM dm_activity WHERE kind='blocked'")
    e.note(json.dumps(sysdb(top(3, 'actor, text, target', "FROM dm_activity WHERE kind='blocked' ORDER BY id DESC"))))
    e.check(int(after) - int(before) >= 3, 'blocked activity rows written')
    return e.save()


def check_uncovered():
    e = Evidence('12-uncovered-db-ai-block')
    e.note('No MongoDB server exists in the stack: a MongoDB service is created pointing at a host that does not resolve.')
    e.note('The AI block runs in the pre-process event, before the service is asked to connect.')

    def cleanup():
        r = req('GET', 'system/service?filter=' + Q("name = 'enf_mongo'") + '&fields=id')
        for s in rows(r) if r['status'] == 200 else []:
            if isinstance(s, dict) and s.get('id'):
                req('DELETE', f"system/service/{s['id']}")

    cleanup()
    try:
        r = req('POST', 'system/service', body={'resource': [{'name': 'enf_mongo', 'label': 'Enforcement mongo (no server)', 'type': 'mongodb', 'is_active': True,
                                                               'config': {'host': 'enf-no-such-mongo.invalid', 'port': 27017, 'database': 'enf',
                                                                          'username': 'enf', 'password': 'EnfNoSuchPass2026', 'options': {'connectTimeoutMS': 1000, 'serverSelectionTimeoutMS': 1000}}}]})
        e.show(r, title='create a MongoDB service (no server behind it)')
        e.check(r['status'] in (200, 201), 'uncovered service created')
        with ModeOn():
            r = req('GET', 'enf_mongo/_table/people', headers={'X-DreamFactory-Trace-Id': 'enf-ai-trace-0200'}, timeout=30)
            e.show(r, title='AI session -> uncovered DB service')
            e.check(r['status'] == 403 and 'Data Masking blocks AI access to services it cannot mask.' in r['text'], '403 with the contract message')
            e.check('because it carries X-DreamFactory-Trace-Id' in r['text'], 'the 403 names the trace header as the reason')
            r = req('GET', 'enf_mongo/_spec?model=true', headers={'X-DreamFactory-Trace-Id': 'enf-ai-trace-0203'}, timeout=30)
            e.show(r, title='AI session -> _spec?model=true of the uncovered service (skips API events)')
            e.check(r['status'] == 403 and 'Data Masking blocks AI access' in r['text'], '_spec of an uncovered service blocked for AI')
            r = req('GET', 'enf_mongo/_table/people', auth='apikey', headers={'X-DreamFactory-Trace-Id': 'enf-ai-trace-0202'}, timeout=30)
            e.show(r, title='AI session with an app API key -> uncovered DB service')
            e.check(r['status'] in (401, 403), 'blocked (403 from masking, or the role has no access at all)')
            r = req('GET', 'enf_mongo/_table/people', timeout=30)
            e.show(r, title='human admin -> same service (unaffected by masking: DreamFactory tries to connect)')
            e.check('Data Masking' not in r['text'], 'humans are not blocked by masking')
        r = req('GET', 'enf_mongo/_table/people', headers={'X-DreamFactory-Trace-Id': 'enf-ai-trace-0201'}, timeout=30)
        e.check('Data Masking blocks' not in r['text'], 'preview mode: AI not blocked (only on)')
        last = '\t'.join(sum(sysdb(top(1, 'actor, text, target', "FROM dm_activity WHERE kind='blocked' ORDER BY id DESC")), []))
        e.note('latest blocked activity: ' + last)
        e.check('cannot mask' in last, 'activity blocked row')
    finally:
        cleanup()
        e.note('cleanup: ' + req('GET', 'system/service?filter=' + Q("name = 'enf_mongo'") + '&fields=id')['text'])
    return e.save()


def check_cache():
    e = Evidence('13-service-cache-caller-safety')
    real = real_customer(3)
    svc = req('GET', f'system/service/{service_id("crm_mysql")}')['json']
    cfg = dict(svc.get('config') or {})
    e.note(f"crm_mysql cache_enabled before: {cfg.get('cache_enabled')}")
    original = access()
    try:
        r = req('PATCH', f'system/service/{service_id("crm_mysql")}', body={'config': dict(cfg, cache_enabled=True, cache_ttl=300)})
        e.check(r['status'] == 200, 'enabled service caching on crm_mysql')
        e.check(req('GET', f'system/service/{service_id("crm_mysql")}')['json']['config'].get('cache_enabled') in (True, 1, '1', 'true'), 'cache_enabled persisted')
        with ModeOn():
            set_access({'admins': {'mode': 'selected', 'grants': [{'admin_id': admin_id(), 'duration': '1h'}]}})
            url = 'crm_mysql/_table/customers?ids=3&fields=id,email,ssn'
            a = req('GET', url)                       # privileged first: fills the cache with real values
            b = req('GET', url, auth='apikey')        # masked caller, same URL/params -> same cache key
            e.show(a, title='1) granted admin (fills the cache)')
            e.show(b, title='2) role user, same URL')
            e.check(rows(a)[0]['email'] == real['email'], 'admin real')
            e.check(rows(b)[0]['email'].startswith('EMAIL_') and real['email'] not in b['text'], 'role user masked: no real value from another caller')
            url2 = 'crm_mysql/_table/customers?ids=4&fields=id,email'
            c = req('GET', url2, auth='apikey')       # masked caller first
            d = req('GET', url2)                      # privileged second
            e.show(c, title='3) role user first (fills the cache)')
            e.show(d, title='4) granted admin, same URL')
            e.check(rows(c)[0]['email'].startswith('EMAIL_'), 'role user masked')
            e.check(rows(d)[0]['email'] == mysql('SELECT email FROM customers WHERE id=4'), 'admin gets real values from the same cache entry')
    finally:
        req('PATCH', f'system/service/{service_id("crm_mysql")}', body={'config': dict(cfg)})
        set_access({'admins': {'mode': original['admins']['mode'], 'grants': [{'admin_id': g['admin_id']} for g in original['admins']['grants']]}})
        e.note('restored: cache_enabled=' + str(req('GET', f'system/service/{service_id("crm_mysql")}')['json']['config'].get('cache_enabled')))
    return e.save()


PROC = """
DROP PROCEDURE IF EXISTS enf_top_customers;
CREATE PROCEDURE enf_top_customers() SELECT id, email, ssn, notes, CONCAT('reach ', email) AS contact_line FROM customers ORDER BY id LIMIT 3;
DROP FUNCTION IF EXISTS enf_contact;
CREATE FUNCTION enf_contact(cid INT) RETURNS VARCHAR(300) DETERMINISTIC READS SQL DATA RETURN (SELECT CONCAT('mail ', email, ' or call ', phone) FROM customers WHERE id = cid);
"""


def check_proc():
    e = Evidence('14-proc-best-effort')
    real = real_customer(1)
    e.note('The corpus PostgreSQL database is read-only for these suites, so the routine lives in the MySQL DB crm_mysql.')
    mysql(PROC)
    try:
        req('GET', 'crm_mysql/_proc?refresh=true')
        with ModeOn():
            r = req('POST', 'crm_mysql/_proc/enf_top_customers', body={})
            e.show(r, title='POST crm_mysql/_proc/enf_top_customers (admin, masked by default)', trim=1200)
            e.check(r['status'] == 200, 'procedure ran')
            e.check(real['email'] not in r['text'] and real['ssn'] not in r['text'], 'no raw email/ssn in the result')
            e.check('EMAIL_' in r['text'], 'email cells tokenized by column name')
            e.check(r['headers'].get('X-DreamFactory-Masked-Fields') == '*', 'X-DreamFactory-Masked-Fields: *')
            r = req('GET', 'crm_mysql/_func/enf_contact?cid=1')
            e.show(r, title='GET crm_mysql/_func/enf_contact?cid=1 (scalar result, span masked)')
            e.check(r['status'] == 200 and real['email'] not in r['text'] and real['phone'] not in r['text'], 'function result: no raw email/phone')
    finally:
        mysql('DROP PROCEDURE IF EXISTS enf_top_customers; DROP FUNCTION IF EXISTS enf_contact')
    return e.save()



def check_mcp():
    from mcp import Session
    e = Evidence('15-mcp-daemon')
    e.note('Real df-mcp-server daemon (service crm_mcp, bound to crm), authenticated with the mobile-app API key.')
    e.note('The daemon calls DreamFactory with X-DreamFactory-Trace-Id, so its calls are AI sessions (ai = masked).')
    emails = set(pg('SELECT "EMail" FROM "CustomerContacts" WHERE "EMail" IS NOT NULL'))
    phones = set(pg('SELECT "MobilePhone" FROM "CustomerContacts" WHERE "MobilePhone" IS NOT NULL'))
    e.note(f'{len(emails)} real CustomerContacts emails read from Postgres (read-only) for the value check')
    original = access()
    role = req('GET', f'system/role/{role_id()}?related=role_service_access_by_role_id')['json']
    keep = [{k: a[k] for k in ('id', 'role_id', 'service_id', 'component', 'verb_mask', 'requestor_mask', 'filters', 'filter_op')}
            for a in role['role_service_access_by_role_id']]
    e.note('role support access before: ' + json.dumps([(a['service_id'], a['component']) for a in keep]))
    try:
        # get_data_model reads crm/_spec, which the support role cannot read: grant it for this check only.
        r = req('PATCH', f'system/role/{role_id()}?related=role_service_access_by_role_id',
                body={'role_service_access_by_role_id': keep + [{'service_id': service_id('crm'), 'component': '_spec', 'verb_mask': 1, 'requestor_mask': 1}]})
        e.check(r['status'] == 200, 'temporarily granted role support GET crm/_spec')
        with ModeOn():
            # Give the app's role real values for REST calls, to show the AI session stays masked anyway.
            set_access({'roles': [{'role_id': role_id(), 'enabled': True, 'scope': 'all'}]})
            rest = req('GET', 'crm/_table/CustomerContacts?limit=3&fields=ContactID,EMail', auth='apikey')
            e.show(rest, title='REST with the same API key (role granted real values): real')
            e.check(any(r.get('EMail') in emails for r in rows(rest)), 'REST caller sees real values (role access scope all)')
            s = Session({'X-DreamFactory-API-Key': API_KEY})
            s.start()
            st, body, m = s.call('get_data_model', {'refresh': True})
            text = json.dumps(m)
            e.lines.append('\n## MCP tools/call get_data_model')
            e.lines.append(body[:1200] + ' …')
            e.check(st == 200 and m and 'result' in m, 'get_data_model answered')
            e.check(not any(x in text for x in emails), 'no real email anywhere in the data model')
            e.check(not any(x in text for x in phones), 'no real mobile phone anywhere in the data model')
            e.check('EMAIL_' in text, 'sample emails are tokens')
            st, body, m = s.call('get_table_data', {'table_name': 'CustomerContacts', 'limit': 5})
            text = json.dumps(m)
            e.lines.append('\n## MCP tools/call get_table_data CustomerContacts limit 5')
            e.lines.append(body[:1200] + ' …')
            e.check(st == 200 and 'EMAIL_' in text, 'get_table_data masked')
            e.check(not any(x in text for x in emails) and not any(x in text for x in phones), 'no real email/phone in get_table_data')
            st, body, m = s.call('get_table_data', {'table_name': 'CustomerContacts', 'filter': "EMail like '%a%'", 'count_only': True})
            e.lines.append('\n## MCP get_table_data with a LIKE filter on a masked column')
            e.lines.append(body[:600])
            e.check(m and m.get('result', {}).get('content', [{}])[0].get('text') == '0', 'LIKE filter on a masked column matches no rows for the AI (count 0)')
    finally:
        set_access({'roles': [{'role_id': x['role_id'], 'enabled': x['enabled'], 'scope': x['scope']} for x in original['roles']]})
        e.note('restored masking role access: ' + json.dumps(access()['roles']))
        current = req('GET', f'system/role/{role_id()}?related=role_service_access_by_role_id')['json']['role_service_access_by_role_id']
        keep_ids = {a['id'] for a in keep}
        extra = [{'id': a['id'], 'role_id': None} for a in current if a['id'] not in keep_ids]
        if extra:
            req('PATCH', f'system/role/{role_id()}?related=role_service_access_by_role_id', body={'role_service_access_by_role_id': extra})
        after = req('GET', f'system/role/{role_id()}?related=role_service_access_by_role_id')['json']['role_service_access_by_role_id']
        e.note('role support access after: ' + json.dumps([(a['service_id'], a['component']) for a in after]))
        e.check(sorted((a['service_id'], a['component']) for a in after) == sorted((a['service_id'], a['component']) for a in keep), 'role access restored')
    return e.save()


def check_agents():
    e = Evidence('16-df-agents-ai-detection')
    e.note('A df-agents agent (role support) calls the REST API with its own key. The role is granted real values for')
    e.note('humans/apps; the agent must still be masked (its key resolves to df.agent / backing app "agent:<id>").')
    original = access()
    agent_id = None
    try:
        r = req('POST', 'agents/agents', body={'resource': [{'name': 'enf_probe_agent', 'role_id': role_id(), 'owner_id': admin_id(), 'key_ttl_hours': 1}]})
        e.show(r, title='create agent')
        agent_id = rows(r)[0].get('id') if r['status'] in (200, 201) else None
        e.check(agent_id is not None, 'agent created')
        key = sysdb_value(f'SELECT api_key FROM agents WHERE id={agent_id}') if agent_id else ''
        e.check(len(key) > 20, 'agent key read from the system DB')
        with ModeOn():
            set_access({'roles': [{'role_id': role_id(), 'enabled': True, 'scope': 'all'}]})
            human = req('GET', 'crm_mysql/_table/customers/1', auth='apikey')
            e.show(human, title='mobile-app (same role, not an agent): real values')
            e.check(human['json'].get('email') == real_customer(1)['email'], 'app sees real values')
            r = req('GET', 'crm_mysql/_table/customers/1', auth=None, headers={'X-DreamFactory-API-Key': key})
            e.show(r, title='agent key (no trace header): masked as an AI session')
            e.check(r['status'] == 200 and str(r['json'].get('email', '')).startswith('EMAIL_'), 'agent masked')
            last = sysdb_value(top(1, 'actor', 'FROM dm_activity ORDER BY id DESC'))
            e.note('latest activity actor: ' + last)
    finally:
        set_access({'roles': [{'role_id': x['role_id'], 'enabled': x['enabled'], 'scope': x['scope']} for x in original['roles']]})
        if agent_id:
            d = req('DELETE', f'agents/agents/{agent_id}')
            e.note(f'deleted agent: {d["status"]}')
        left = req('GET', 'system/app?filter=' + Q("name like 'agent:%'") + '&fields=id,name')['text']
        e.note('backing apps left: ' + left)
    return e.save()


def check_unscanned():
    e = Evidence('17-unscanned-column-inline')
    e.note('Columns added after the scan (crm_mysql.customers.backup_email, and alt_contact, whose name says nothing) are')
    e.note('classified inline by name, stored in dm_column (source detected, scanned_at null) and enforced at once: a text')
    e.note('column whose name says nothing is span-masked until scanned. A scan of the service starts')
    e.note('within seconds (at most one such scan per service per minute, a later one runs at its end).')
    mysql("ALTER TABLE customers ADD COLUMN backup_email VARCHAR(255) NULL, ADD COLUMN alt_contact VARCHAR(255) NULL")
    mysql("UPDATE customers SET backup_email = CONCAT('alt.', email), alt_contact = CONCAT('c.', email)")
    svc = service_id('crm_mysql')
    try:
        req('GET', 'crm_mysql/_schema/customers?refresh=true')
        last_scan = sysdb_value("SELECT COALESCE(MAX(id), 0) FROM dm_scan")
        with ModeOn():
            r = req('GET', 'crm_mysql/_table/customers/1?fields=id,backup_email,alt_contact', auth='apikey')
            e.show(r, title='first request after the columns appeared')
            raw = mysql('SELECT backup_email FROM customers WHERE id=1')
            raw2 = mysql('SELECT alt_contact FROM customers WHERE id=1')
            body = r['json'] if isinstance(r.get('json'), dict) else {}
            e.check(r['status'] == 200 and body.get('backup_email') != raw and masked(body.get('backup_email')), 'new column masked on the first request')
            e.check(body.get('alt_contact') != raw2 and '@' not in str(body.get('alt_contact')), 'innocuous-named email column masked on the first request (span)')
        found = sysdb(f"SELECT column_name, verdict, class, source, CASE WHEN scanned_at IS NULL THEN 'NULL' ELSE 'set' END FROM dm_column WHERE service_id={svc} AND table_name='customers' AND column_name IN ('backup_email', 'alt_contact') ORDER BY column_name")
        e.note('dm_column rows right after the request: ' + json.dumps(found))
        e.check(raw not in json.dumps(found) and raw2 not in json.dumps(found), 'no value stored')
        started = None
        for _ in range(10):
            rows = sysdb(f"SELECT id, status FROM dm_scan WHERE id > {last_scan} AND service_id = {svc}")
            if rows:
                started = rows
                break
            time.sleep(0.5)
        e.note('dm_scan rows of crm_mysql since the request: ' + json.dumps(started))
        e.check(started is not None, 'a scan of crm_mysql started within 5 seconds')
        for _ in range(60):
            after = sysdb(f"SELECT verdict, class, CASE WHEN scanned_at IS NULL THEN 'NULL' ELSE 'set' END FROM dm_column WHERE service_id={svc} AND table_name='customers' AND column_name='alt_contact'")
            if after and after[0][2] == 'set':
                break
            time.sleep(1)
        e.note('alt_contact after the scan: ' + json.dumps(after))
        e.check(bool(after) and after[0][:2] == ['masked', 'email'], 'the scan classified alt_contact from its values')
    finally:
        mysql("ALTER TABLE customers DROP COLUMN backup_email, DROP COLUMN alt_contact")
        req('GET', 'crm_mysql/_schema/customers?refresh=true')
        sysdb(f"DELETE FROM dm_column WHERE service_id={svc} AND table_name='customers' AND column_name IN ('backup_email', 'alt_contact')")
        set_access({'ai': access()['ai']})  # bump the policy version after the direct delete
        e.note('cleanup: columns dropped, dm_column rows removed')
    return e.save()


def check_queries():
    e = Evidence('19-zero-queries-off-and-uncovered')
    e.note('MySQL general log (system DB server) captures every query while requests run; only dm_* tables count.')
    e.note('Other agents share the stack: any dm_* query from them could only add rows, never hide ours.')
    state = mysql("SELECT @@global.general_log, @@global.log_output", db='mysql').split('\t')
    prev = mode()

    def run(label, setup_mode, calls):
        set_mode(setup_mode)
        for path, auth in calls[:3]:
            req('GET', path, auth=auth)  # warm caches after the mode change
        mysql("SET GLOBAL log_output='TABLE'; TRUNCATE mysql.general_log; SET GLOBAL general_log='ON';", db='mysql')
        for _ in range(5):
            for path, auth in calls:
                r = req('GET', path, auth=auth)
                assert r['status'] < 500, r['text'][:200]
        mysql("SET GLOBAL general_log='OFF';", db='mysql')
        total = mysql("SELECT COUNT(*) FROM mysql.general_log WHERE command_type IN ('Query','Execute')", db='mysql')
        dm = mysql("SELECT argument FROM mysql.general_log WHERE command_type IN ('Query','Execute') AND argument LIKE '%dm\\_%'", db='mysql')
        dm_rows = [x for x in dm.splitlines() if x.strip()]
        e.note(f'\n## {label}: {total} queries logged in the window, {len(dm_rows)} on dm_* tables')
        for q in dm_rows[:10]:
            e.note('  ' + q[:200])
        return dm_rows

    try:
        off = run('mode off, covered table reads (role user)', 'off',
                  [('crm_mysql/_table/customers?limit=50', 'apikey'), ('crm_mysql/_table/orders?limit=50&related=customers_by_customer_id', 'apikey')])
        e.check(off == [], 'mode off: zero df-masking queries')
        unc = run('mode on, requests to non-database services (admin)', 'on',
                  [('system/environment', 'admin'), ('system/role?fields=id', 'admin'), ('user/profile', 'admin')])
        e.check(unc == [], 'mode on, uncovered requests: zero df-masking queries')
        cov = run('mode on, covered table reads (warm caches)', 'on', [('crm_mysql/_table/customers?limit=50', 'apikey')])
        e.check(cov == [], 'mode on, covered reads on warm caches: zero df-masking queries (policy, settings, access all cached)')
    finally:
        mysql(f"SET GLOBAL general_log='OFF'; SET GLOBAL log_output='{state[1] if len(state) > 1 else 'FILE'}'; TRUNCATE mysql.general_log;", db='mysql')
        if mode() != prev:
            set_mode(prev)
        e.note(f'restored general_log=OFF (was {state[0]}), log_output={state[1] if len(state) > 1 else "?"}; mode {mode()}')
    return e.save()

IGNORED_HEADERS = [
    {'X-DreamFactory-Masking': 'off'},
    {'X-DreamFactory-Masking-View': 'real'},
    {'X-DreamFactory-Masking-View': 'masked'},
    {'X-DreamFactory-Masked-Fields': 'id'},
    {'X-DreamFactory-Masking-Rewrites': 'filter:id'},
]


def check_ignored_headers():
    e = Evidence('20-ignored-request-headers')
    real = real_customer(1)
    e.note('Masking headers are response-only. Requests that carry them must get the same status, body and masking headers as without.')
    with ModeOn():
        for title, path, auth in [
            ('app API key, masked', 'crm_mysql/_table/customers/1?fields=email,ssn', 'apikey'),
            ('app API key, rewritten filter', 'crm_mysql/_table/customers?fields=id&limit=1&filter=' + Q("ssn like '1%'"), 'apikey'),
        ]:
            base = req('GET', path, auth=auth)
            e.show(base, title=title + ': baseline')
            e.check(base['status'] == 200 and masking_headers(base) != {}, f'{title}: baseline has a masking header')
            for h in IGNORED_HEADERS:
                r = req('GET', path, auth=auth, headers=h)
                e.show(r, title=f'{title}: with {json.dumps(h)}')
                same = (r['status'], r['text'], masking_headers(r)) == (base['status'], base['text'], masking_headers(base))
                e.check(same, f'{title}: {json.dumps(h)} changes nothing')
            e.check(real['email'] not in base['text'] and real['ssn'] not in base['text'], f'{title}: no raw values')
    return e.save()



CHECKS = {
    'formats': check_formats, 'related': check_single_related, 'filters': check_filters, 'writes': check_writes,
    'errors': check_errors, 'script': check_script, 'platform_api': check_platform_api, 'spec': check_spec,
    'preview': check_preview, 'access': check_access_ai, 'ai_settings': check_ai_settings, 'uncovered': check_uncovered,
    'cache': check_cache, 'proc': check_proc, 'mcp': check_mcp, 'agents': check_agents, 'unscanned': check_unscanned, 'queries': check_queries,
    'ignored_headers': check_ignored_headers,
}

if __name__ == '__main__':
    refresh_tokens()
    names = sys.argv[1:] or ['all']
    if names == ['all']:
        names = list(CHECKS)
    ok = True
    for n in names:
        try:
            ok = CHECKS[n]() and ok
        except Exception as ex:  # report and continue
            import traceback
            traceback.print_exc()
            print(f'[{n}] ERROR {ex}')
            ok = False
    print('ALL PASS' if ok else 'SOME FAILED')
    print('mode now:', mode())
    sys.exit(0 if ok else 1)
