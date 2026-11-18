"""Minimal MCP (streamable HTTP) client for a DreamFactory MCP service (DM_MCP_URL). Stdlib only."""
import json
import os
import urllib.error
import urllib.request

URL = os.environ.get('DM_MCP_URL', 'http://127.0.0.1/mcp/crm_mcp')
# The daemon runs next to DreamFactory and calls back to the Host it was reached on; 'localhost' works in the
# reference stack (no MCP_INTERNAL_BASE_URL). Override with DM_MCP_HOST.
HOST = os.environ.get('DM_MCP_HOST', 'localhost')


def _post(payload, headers):
    # Host: localhost -> the daemon (inside the web container) calls back http://localhost/api/v2 (nginx).
    h = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream', 'Host': HOST}
    h.update(headers)
    r = urllib.request.Request(URL, data=json.dumps(payload).encode(), method='POST', headers=h)
    try:
        resp = urllib.request.urlopen(r, timeout=120)
        status, rh, body = resp.status, dict(resp.headers), resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        status, rh, body = e.code, dict(e.headers), e.read().decode('utf-8', 'replace')
    msgs = []
    if 'text/event-stream' in rh.get('Content-Type', ''):
        for line in body.splitlines():
            if line.startswith('data:'):
                try:
                    msgs.append(json.loads(line[5:].strip()))
                except ValueError:
                    pass
    else:
        try:
            msgs.append(json.loads(body))
        except ValueError:
            pass
    return status, rh, body, msgs


class Session:
    def __init__(self, auth_headers):
        self.h = dict(auth_headers)
        self.n = 0

    def rpc(self, method, params=None, notify=False):
        payload = {'jsonrpc': '2.0', 'method': method}
        if params is not None:
            payload['params'] = params
        if not notify:
            self.n += 1
            payload['id'] = self.n
        status, rh, body, msgs = _post(payload, self.h)
        sid = rh.get('Mcp-Session-Id') or rh.get('mcp-session-id')
        if sid:
            self.h['Mcp-Session-Id'] = sid
        return status, body, (msgs[-1] if msgs else None)

    def start(self):
        s, body, m = self.rpc('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'enf-probe', 'version': '1'}})
        self.rpc('notifications/initialized', notify=True)
        return s, body, m

    def call(self, tool, args):
        return self.rpc('tools/call', {'name': tool, 'arguments': args})
