"""Shared helpers for the df-masking live suites (stdlib only, Python 3.8+).

The suites run against a real DreamFactory 7.8 Gold instance with df-masking installed and the
reference fixtures described in tests/Live/README.md. Everything stack-specific comes from the
environment; the variables marked (required) have no default:

  DM_BASE_URL            (required) for example http://127.0.0.1/api/v2/
  DM_ADMIN_EMAIL / DM_ADMIN_PASSWORD      (required) the df-compliance root admin
  DM_ADMIN2_EMAIL / DM_ADMIN2_PASSWORD    (required) a second, non-root admin
  DM_API_KEY             (required) API key of an app whose role is DM_ROLE (GET on crm and crm_mysql tables)
  DM_ROLE                support
  DM_MYSQL               (required) command prefix that runs the mysql client against the MySQL server
                         holding crm_mysql, for example
                           docker exec -e MYSQL_PWD dreamfactory_mysql_1 mysql -uroot
  DM_SYSDB               command prefix of the system database's client, ending with what selects the
                         database (default: DM_MYSQL + "dreamfactory"), for example
                           docker exec dreamfactory_pg_1 psql -U postgres -d dfsys
                           docker exec dreamfactory_mssql /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -d dm_sys
                           docker exec web /opt/dreamfactory/storage/databases/dm_sys.sqlite
                         (SQLite: the exec prefix and the database file; PHP's PDO runs the query, so
                         no sqlite3 client is needed in the container)
  DM_SYSDB_DIALECT       mysql (default) | pgsql | sqlsrv | sqlite
  DM_PG                  command prefix that runs psql against the PostgreSQL corpus DB (optional:
                         without it the MCP check has no corpus values to search responses for)
  DM_DOCKER              "sudo -n docker" (or "docker")
  DM_EVIDENCE_DIR        where transcripts go (default: $TMPDIR/df-masking-live)

Transcripts contain the stack's synthetic test data; never point these suites at real data.
Every check that changes shared state (mode, access, service config) restores it in `finally`.
"""
import json
import os
import shlex
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request



def _required(name):
    value = os.environ.get(name, '')
    if not value:
        raise SystemExit(f'{name} is not set: see tests/Live/README.md for the environment these suites need.')
    return value


BASE = _required('DM_BASE_URL').rstrip('/') + '/'
ADMIN = (_required('DM_ADMIN_EMAIL'), _required('DM_ADMIN_PASSWORD'))
ADMIN2 = (_required('DM_ADMIN2_EMAIL'), _required('DM_ADMIN2_PASSWORD'))
API_KEY = _required('DM_API_KEY')
ROLE = os.environ.get('DM_ROLE', 'support')
DOCKER = shlex.split(os.environ.get('DM_DOCKER', 'sudo -n docker'))
MYSQL = shlex.split(_required('DM_MYSQL'))
SYSDB = shlex.split(os.environ['DM_SYSDB']) if os.environ.get('DM_SYSDB') else MYSQL + ['dreamfactory']
SYSDB_DIALECT = os.environ.get('DM_SYSDB_DIALECT', 'mysql')
PG = shlex.split(os.environ.get('DM_PG', ''))
EVID = os.environ.get('DM_EVIDENCE_DIR', os.path.join(tempfile.gettempdir(), 'df-masking-live'))
G = '•'

os.makedirs(EVID, exist_ok=True)
_tokens = {}


def _login(email, password):
    data = ('email=' + urllib.parse.quote(email) + '&password=' + urllib.parse.quote(password)).encode()
    r = urllib.request.Request(BASE + 'system/admin/session', data=data, method='POST',
                               headers={'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'})
    with urllib.request.urlopen(r, timeout=60) as resp:
        return json.loads(resp.read())['session_token']


def refresh_tokens():
    _tokens['admin'] = _login(*ADMIN)
    _tokens['admin2'] = _login(*ADMIN2)


def token(name='admin'):
    if name not in _tokens:
        refresh_tokens()
    return _tokens[name]


def req(method, path, auth='admin', body=None, headers=None, raw=False, timeout=60):
    url = BASE + path
    h = {'Accept': 'application/json'}
    if auth in ('admin', 'admin2', 'priya'):
        h['X-DreamFactory-Session-Token'] = token('admin2' if auth == 'priya' else auth)
    elif auth == 'apikey':
        h['X-DreamFactory-API-Key'] = API_KEY
    if headers:
        h.update(headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h['Content-Type'] = 'application/json'
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    t0 = time.perf_counter()
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        status, rh, payload = resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        status, rh, payload = e.code, dict(e.headers), e.read()
    ms = (time.perf_counter() - t0) * 1000
    text = payload.decode('utf-8', 'replace')
    parsed = None
    if not raw:
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
    return {'status': status, 'headers': rh, 'text': text, 'json': parsed, 'ms': ms, 'method': method, 'path': path,
            'auth': auth, 'req_headers': {k: v for k, v in (headers or {}).items()}}


class Evidence:
    def __init__(self, name):
        self.name = name
        self.lines = []
        self.failures = []

    def note(self, s):
        self.lines.append(s)

    def show(self, r, trim=900, title=None):
        mh = {k: v for k, v in r['headers'].items() if k.lower().startswith('x-dreamfactory-mask') or k.lower() == 'content-type'}
        self.lines.append('')
        if title:
            self.lines.append('## ' + title)
        extra = (' headers=' + json.dumps(r['req_headers'])) if r['req_headers'] else ''
        self.lines.append(f"> {r['method']} /api/v2/{r['path']}  (auth={r['auth']}){extra}")
        self.lines.append(f"< {r['status']}  {json.dumps(mh)}  [{r['ms']:.0f} ms]")
        body = r['text']
        self.lines.append(body[:trim] + (' ...' if len(body) > trim else ''))

    def check(self, cond, what):
        self.lines.append(('PASS ' if cond else 'FAIL ') + what)
        if not cond:
            self.failures.append(what)
        return cond

    def save(self):
        path = os.path.join(EVID, self.name + '.txt')
        with open(path, 'w') as f:
            f.write(f"# {self.name}  ({time.strftime('%Y-%m-%d %H:%M:%S %Z')})\n")
            f.write('\n'.join(self.lines) + '\n')
            f.write('\nRESULT: ' + ('PASS' if not self.failures else 'FAIL: ' + '; '.join(self.failures)) + '\n')
        print(f"[{self.name}] {'PASS' if not self.failures else 'FAIL'} -> {path}")
        for f_ in self.failures:
            print('   FAIL:', f_)
        return not self.failures


def mode():
    return req('GET', 'system/data_masking')['json']['mode']


def set_mode(m):
    r = req('PATCH', 'system/data_masking', body={'mode': m})
    assert r['status'] == 200, r['text'][:300]
    return r


def access():
    return req('GET', 'system/data_masking/access')['json']


def set_access(body):
    r = req('PATCH', 'system/data_masking/access', body=body)
    assert r['status'] == 200, r['text'][:400]
    return r['json']


class ModeOn:
    """with ModeOn(): ... switches to mode on and restores the previous mode."""

    def __init__(self, m='on'):
        self.m = m

    def __enter__(self):
        self.prev = mode()
        if self.prev != self.m:
            set_mode(self.m)
        return self

    def __exit__(self, *a):
        if self.prev != self.m:
            set_mode(self.prev)


def mysql(sql, db='crm_mysql'):
    out = subprocess.run(MYSQL + ['-N', '-B', db, '-e', sql], capture_output=True, text=True)
    return out.stdout.strip()


_SQLITE_PHP = ('$p = new PDO("sqlite:" . $argv[1]); $p->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); $s = $p->query($argv[2]);'
               ' if ($s) { foreach ($s->fetchAll(PDO::FETCH_NUM) as $r) { echo implode("\t", array_map(fn ($v) => $v === null ? "NULL" : $v, $r)), "\n"; } }')


def sysdb(sql):
    """Rows (lists of strings, NULL as 'NULL') of a query on the DreamFactory system database, whatever
    its type (DM_SYSDB / DM_SYSDB_DIALECT). Keep the SQL portable: plain SELECT/UPDATE/DELETE, no LIMIT
    (use top()), timestamps as 'YYYY-MM-DD HH:MM:SS' literals (utc_ago())."""
    tab = '\t'
    cmd = {
        'mysql': SYSDB + ['-N', '-B', '-e', sql],
        'pgsql': SYSDB + ['-At', '-F', tab, '-P', 'null=NULL', '-c', sql],
        'sqlsrv': SYSDB + ['-h', '-1', '-W', '-s', tab, '-Q', 'SET NOCOUNT ON; ' + sql],
        'sqlite': SYSDB[:-1] + ['php', '-r', _SQLITE_PHP, SYSDB[-1], sql],
    }[SYSDB_DIALECT]
    out = subprocess.run(cmd, capture_output=True, text=True)
    return [line.split(tab) for line in out.stdout.splitlines() if line.strip()]


def sysdb_value(sql):
    """First column of the first row, '' when there is none."""
    rows = sysdb(sql)
    return rows[0][0] if rows and rows[0] else ''


def top(n, columns, rest):
    """Portable "first n rows": top(1, 'actor, text', "FROM dm_activity WHERE kind='blocked' ORDER BY id DESC")."""
    if SYSDB_DIALECT == 'sqlsrv':
        return f'SELECT TOP {int(n)} {columns} {rest}'
    return f'SELECT {columns} {rest} LIMIT {int(n)}'


def utc_ago(seconds):
    """A UTC timestamp literal `seconds` ago (DreamFactory stores UTC)."""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time() - seconds))


def pg(sql):
    """Rows from the PostgreSQL corpus DB (DM_PG); none when DM_PG is not set."""
    if not PG:
        return []
    out = subprocess.run(PG + ['-At', '-c', sql], capture_output=True, text=True)
    return [x for x in out.stdout.splitlines() if x.strip()]


_ids = {}


def service_id(name):
    """DreamFactory service id by name (looked up once)."""
    key = 'service:' + name
    if key not in _ids:
        r = req('GET', 'system/service?fields=id&filter=' + urllib.parse.quote(f"name = '{name}'"))
        _ids[key] = int(r['json']['resource'][0]['id'])
    return _ids[key]


def role_id(name=None):
    key = 'role:' + (name or ROLE)
    if key not in _ids:
        r = req('GET', 'system/role?fields=id&filter=' + urllib.parse.quote(f"name = '{name or ROLE}'"))
        _ids[key] = int(r['json']['resource'][0]['id'])
    return _ids[key]


def admin_id(email=None):
    key = 'admin:' + (email or ADMIN[0])
    if key not in _ids:
        r = req('GET', 'system/admin?fields=id&filter=' + urllib.parse.quote(f"email = '{email or ADMIN[0]}'"))
        _ids[key] = int(r['json']['resource'][0]['id'])
    return _ids[key]


def masked(v):
    return v is None or (isinstance(v, str) and (G in v or (v.split('_')[0].isupper() and len(v.split('_')[-1]) == 8)))


def masking_headers(r):
    """The Data Masking response headers of a response (names lower-cased)."""
    return {k.lower(): v for k, v in r['headers'].items() if k.lower().startswith('x-dreamfactory-mask')}


def listed(r, name):
    """Items of a list header ("a, b, +2 more"), split on "," and trimmed."""
    return {i.strip() for i in (r['headers'].get(name) or '').split(',') if i.strip()}


def rows(r):
    j = r['json']
    if isinstance(j, dict) and 'resource' in j:
        return j['resource']
    return j if isinstance(j, list) else [j]

