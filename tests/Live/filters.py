"""Filter/order/group/fields probes, mode on, role user (API key). Prints counts/headers only.

A comparison the caller may not make on a masked column is unknown (SQL NULL), so it
matches no rows (0), never more rows; OR keeps the clear side. Header filter:<col> = "conditions on
<col> matched no rows"."""
import json, os, sys, urllib.parse
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from live import req, mysql, set_mode, mode, G
Q = urllib.parse.quote
total = int(mysql('SELECT COUNT(*) FROM customers'))
real = dict(zip(['email', 'ssn', 'state'], mysql('SELECT email, ssn, state FROM customers WHERE id=7').split('\t')))
il = int(mysql("SELECT COUNT(*) FROM customers WHERE state='IL'"))
prev = mode(); set_mode('on')
results = []
def probe(label, params, expect_count=None, expect_drop=None, auth='apikey', path='crm_mysql/_table/customers'):
    r = req('GET', path + '?' + params, auth=auth)
    j = r['json']
    count = j if isinstance(j, int) else (j.get('meta', {}).get('count') if isinstance(j, dict) else None)
    drop = r['headers'].get('X-DreamFactory-Masking-Rewrites')
    ok = r['status'] == 200
    if expect_count is not None:
        ok = ok and count == expect_count
    if expect_drop is not None:
        ok = ok and (drop == expect_drop if expect_drop != '' else drop is None)
    exposed = any(v and v in r['text'] for v in (real['email'], real['ssn']))
    ok = ok and not exposed
    results.append(ok)
    print(('PASS ' if ok else 'FAIL ') + f"{label:62} status={r['status']} count={count} rewrites={drop}" + (' REAL VALUE IN BODY' if exposed else ''))
    return r
try:
    probe('identity = (OR with clear term): allowed', 'count_only=true&filter=' + Q(f"(email = '{real['email']}') or (state = 'XX')"), 1, '')
    probe('identity IN (2 values): allowed', 'count_only=true&filter=' + Q(f"email in ('{real['email']}','nobody@example.invalid')"), 1, '')
    probe('identity contains: no rows', 'count_only=true&filter=' + Q("email contains 'example'"), 0, 'filter:email')
    probe('identity starts with: no rows', 'count_only=true&filter=' + Q("email starts with 'a'"), 0, 'filter:email')
    probe('identity range >: no rows', 'count_only=true&filter=' + Q("email > 'm'"), 0, 'filter:email')
    probe('restricted IS NOT NULL: allowed', 'count_only=true&filter=' + Q('ssn is not null'), int(mysql('SELECT COUNT(*) FROM customers WHERE ssn IS NOT NULL')), '')
    probe('restricted, upper-case column name, real value: no rows', 'count_only=true&filter=' + Q(f"SSN = '{real['ssn']}'"), 0, None)
    probe('NOT group with masked term: no rows', 'count_only=true&filter=' + Q("not (ssn like '1%')"), 0, 'filter:ssn')
    probe('AND without parentheses: no rows', 'count_only=true&filter=' + Q("state = 'IL' and ssn like '1%'"), 0, 'filter:ssn')
    probe('OR without parentheses keeps the clear side', 'count_only=true&filter=' + Q("state = 'IL' or ssn like '1%'"), il, 'filter:ssn')
    probe('restricted between: no rows', 'count_only=true&filter=' + Q("ssn between '100' and '200'"), 0, 'filter:ssn')
    probe('quasi = (gender): allowed', 'count_only=true&filter=' + Q("gender = 'F'"), int(mysql("SELECT COUNT(*) FROM customers WHERE gender='F'")), '')
    probe('free text = (notes): no rows', 'count_only=true&filter=' + Q("notes = 'x'"), 0, 'filter:notes')
    probe('order by restricted desc: dropped', 'fields=id&limit=2&order=' + Q('ssn desc'), None, 'order:ssn')
    probe('group by identity: dropped', 'fields=' + Q('email,COUNT(*)') + '&group=email&limit=2', None, None)
    probe('having on masked aggregate', 'fields=' + Q('state,COUNT(*)') + '&group=state&having=' + Q("MAX(ssn) > '5'") + '&limit=3', None, None)
    probe('related.order on a masked column of the related table', 'ids=1,2&fields=id&related=payment_methods_by_customer_id&payment_methods_by_customer_id.order=card_number', None, None)
    probe('related.fields with MAX() on a masked column', 'ids=1&fields=id&related=payment_methods_by_customer_id&payment_methods_by_customer_id.fields=' + Q('MAX(card_number)'), None, None)
    probe('include_count with an unknown filter', 'include_count=true&limit=1&fields=id&filter=' + Q("ssn like '9%'"), 0, 'filter:ssn')
    r = req('GET', 'crm_mysql/_table/customers?' + 'filter[]=' + Q("ssn like '1%'") + '&filter[]=' + Q("state = 'IL'") + '&count_only=true', auth='apikey')
    print('INFO filter[] array form: status', r['status'], 'body', r['text'][:120], 'rewrites', r['headers'].get('X-DreamFactory-Masking-Rewrites'))
finally:
    set_mode(prev)
print('ALL PASS' if all(results) else 'SOME FAILED')
sys.exit(0 if all(results) else 1)
