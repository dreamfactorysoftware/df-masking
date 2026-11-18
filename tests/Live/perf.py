"""Enforcement overhead on a 100-row covered GET as the role user, off vs preview vs on (p50)."""
import os, statistics, sys, json, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from live import *  # noqa

URL = 'crm_mysql/_table/customers?limit=100'
N = 50
refresh_tokens()
prev = mode()
samples = {'off': [], 'preview': [], 'on': []}
bytes_ = {}
try:
    for order in (['off', 'preview', 'on'], ['on', 'preview', 'off'], ['preview', 'off', 'on'], ['on', 'off', 'preview']):
        for m in order:
            set_mode(m)
            for _ in range(8):  # warm caches (policy, schema, settings) after the version bump
                req('GET', URL, auth='apikey')
            for _ in range(N // 2):
                r = req('GET', URL, auth='apikey')
                assert r['status'] == 200
                samples[m].append(r['ms'])
            bytes_[m] = len(r['text'])
            assert (m == 'on') == ('EMAIL_' in r['text']), f'unexpected masking state in mode {m}'
finally:
    set_mode(prev)

e = Evidence('18-performance')
e.note(f'GET /api/v2/{URL} as the role user (API key), 16 columns of which 12 masked, 100 rows.')
e.note(f'{2 * N} timed requests per mode in 4 rounds of blocks in rotating order (8 warm-up requests per block). Client-side wall time.')
for m in ('off', 'preview', 'on'):
    s = sorted(samples[m])
    e.note(f'{m:8s} p50 {statistics.median(s):6.1f} ms   p90 {s[int(len(s) * 0.9)]:6.1f} ms   mean {statistics.mean(s):6.1f} ms   body {bytes_[m]} bytes')
d_on = statistics.median(samples['on']) - statistics.median(samples['off'])
d_pre = statistics.median(samples['preview']) - statistics.median(samples['off'])
e.note(f'overhead p50: on - off = {d_on:.1f} ms ; preview - off = {d_pre:.1f} ms  (budget: < 10 ms)')
e.check(d_on < 10, 'masking overhead under 10 ms p50')
ok = e.save()
print(open(EVID + '/18-performance.txt').read())
sys.exit(0 if ok else 1)
