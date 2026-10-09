"""Fixed public synthetic demo behind the owner's HTTPS proxy; persistent state."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
import uuid
from dashboard import serve as ui
from missionguard.demo import fixture_contract, tool_request
from missionguard.http_demo import LocalFixture, post
from missionguard.http_runtime import Runtime, TokenRegistry, initialize_state, private_path
from missionguard.http_server import running_server
from missionguard.policy import AUDIENCE
from missionguard.akash_dataset import AkashDatasetAdapter

HOST = 'missionguard.boriskov.com'
ORIGIN = 'https://' + HOST

def write_once(directory, name, value):
    raw = json.dumps(value, separators=(',', ':')).encode()
    if len(raw) > 131072: raise ValueError('state_bound')
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, raw) != len(raw): raise OSError('short_write')
        os.fsync(fd)
    finally: os.close(fd)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)

def load(directory, name):
    path = private_path(directory / name)
    with path.open('rb') as source: raw = source.read(131073)
    if len(raw) > 131072: raise ValueError('state_bound')
    return json.loads(raw)

def run_persistent(directory, ledger_id, akash_port=None):
    now = int(time.time()); contract = fixture_contract(); contract['expires_at'] = now + 1800; contract['mission_id'] = 'demo-mission-akash-20261009'
    adapter = AkashDatasetAdapter(akash_port) if akash_port is not None else None
    if adapter is not None: contract['connection_ref'] = adapter.connection_ref
    human, agent = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    records = [{'token_hash': hashlib.sha256(token.encode()).hexdigest(), 'actor_id': 'demo-human',
                'org_id': 'demo-org', 'role': role, 'audience': AUDIENCE,
                'mission_ids': [contract['mission_id']], 'expires_at': now + 1800}
               for token, role in ((human, 'human'), (agent, 'agent'))]
    runtime = Runtime(directory, ledger_id, TokenRegistry({'schema_version': '1.0', 'tokens': records}), adapter=adapter)
    try:
        with running_server(runtime) as server:
            fixture = LocalFixture(server.server_address[1], human, agent, contract, runtime)
            status, approved = post(fixture, '/v1/approve', contract, human=True)
            if status != 200: raise ValueError('approval_failed')
            request = tool_request(approved)
            _, allowed = post(fixture, '/v1/execute', request)
            before = runtime.engine.adapter.dispatch_count
            _, replay = post(fixture, '/v1/execute', request)
            replay_count = runtime.engine.adapter.dispatch_count - before
            request['idempotency_key'] = 'http-deny'; request['arguments']['event_ids'] = ['foreign-fictional-event']
            before = runtime.engine.adapter.dispatch_count
            _, denied = post(fixture, '/v1/execute', request)
            denied_count = runtime.engine.adapter.dispatch_count - before
            _, receipt = post(fixture, '/v1/receipt', {'schema_version': '1.0', 'mission_id': approved['mission_id']}, human=True)
            return {'receipt': receipt, 'evidence': {'allowed_status': allowed['status'], 'replayed': replay['replayed'],
                    'replay_new_dispatches': replay_count, 'denial_reason': denied['reason'], 'denied_new_dispatches': denied_count,
                    **({'dataset_upstream_dispatches': adapter.dispatch_count} if adapter is not None else {})}}
    finally: runtime.close()

class PublicHandler(ui.Handler):
    def _local(self):
        return (self.client_address[0] == '127.0.0.1' and self.headers.get_all('Host', []) == [HOST]
                and self.headers.get_all('X-Forwarded-Proto', []) == ['https']
                and sum(len(k)+len(v) for k,v in self.headers.items()) <= 8192)
    def _origin(self):
        return (self._local() and self.headers.get_all('Origin', []) == [ORIGIN]
                and self.headers.get_all('Sec-Fetch-Site', []) == ['same-origin'])
    def do_POST(self):
        if self.path != '/api/demo-run': return self._reply(404, {'error': 'not_found'})
        if (not self._origin() or self.headers.get_all('Content-Type', []) != ['application/json']
                or any(self.headers.get_all(x) for x in ('Transfer-Encoding','Expect','Authorization'))
                or len(self.headers.get_all('Content-Length', [])) != 1):
            return self._reply(403, {'error': 'request_rejected'})
        length = self.headers.get('Content-Length','')
        if not length.isascii() or not length.isdecimal() or not 1 <= int(length) <= 128:
            return self._reply(413, {'error': 'body_bound'})
        try: body = self.rfile.read(int(length))
        except OSError: return self._reply(408, {'error': 'request_timeout'})
        if body != b'{"confirm_policy":"synthetic-read-v1"}':
            return self._reply(400, {'error': 'policy_confirmation_required'})
        with self.server.guard:
            nonce = self.headers.get_all('X-Demo-CSRF', [])
            if (self.server.claimed or self.server.nonce is None or len(nonce) != 1
                    or time.monotonic() > self.server.nonce_deadline
                    or not secrets.compare_digest(nonce[0], self.server.nonce)):
                return self._reply(409, {'error': 'run_unavailable_or_claimed'})
            run_id, started = str(uuid.uuid4()), int(time.time())
            pending = {'run_id': run_id, 'state': 'pending', 'started_at': started}
            try: write_once(self.server.state, 'claim.json', pending)
            except OSError:
                self.server.claimed = True
                return self._reply(503, {'error': 'claim_unknown'})
            self.server.claimed = True; self.server.nonce = None; self.server.result = pending
        try:
            result = run_persistent(self.server.state, self.server.ledger_id, self.server.akash_port)
            envelope = {'schema_version': 'dashboard-run-1', 'run_id': run_id, 'started_at': started,
                        'completed_at': int(time.time()), 'execution_source': 'local_core_http',
                        'caller': 'deterministic_local', 'agent_runtime': 'unavailable', 'dataset': 'synthetic', **result}
            write_once(self.server.state, 'result.json', envelope)
        except Exception:
            envelope = {'run_id': run_id, 'state': 'unknown', 'started_at': started}
            with self.server.guard: self.server.result = envelope
            return self._reply(503, {'error': 'run_unknown', 'run_id': run_id})
        with self.server.guard: self.server.result = envelope
        self._reply(200, envelope)

def create_public_server(directory, port=8768, akash_port=None):
    if akash_port is not None and (type(akash_port) is not int or not 1 <= akash_port <= 65535):
        raise ValueError('invalid_trusted_port')
    directory = private_path(Path(directory), directory=True).resolve()
    ledger_id = load(directory, 'ledger-id.json')['ledger_id']
    if str(uuid.UUID(ledger_id)) != ledger_id: raise ValueError('invalid_ledger_id')
    private_path(directory / 'ledger.sqlite')
    fd = os.open(directory / 'ui.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        private_path(directory / 'ui.lock'); fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        server = ui.create_server(port); server.RequestHandlerClass = PublicHandler
    except BaseException: os.close(fd); raise
    server.state, server.ledger_id, server.private_lock_fd = directory, ledger_id, fd
    server.akash_port = akash_port
    if (directory / 'claim.json').exists():
        server.claimed = True; server.result = load(directory, 'claim.json')
        if (directory / 'result.json').exists(): server.result = load(directory, 'result.json')
    return server

def main():
    p=argparse.ArgumentParser(); p.add_argument('command',choices=('init','serve'));p.add_argument('--state',required=True);p.add_argument('--port',type=int,default=8768);p.add_argument('--akash-port',type=int)
    args=p.parse_args(); directory=Path(args.state)
    if args.command=='init':
        ledger_id=initialize_state(directory);write_once(directory,'ledger-id.json',{'ledger_id':ledger_id});print('initialized');return
    server=create_public_server(directory,args.port,args.akash_port)
    try: print('public_demo_loopback_ready',flush=True);server.serve_forever()
    finally: server.server_close();os.close(server.private_lock_fd)

if __name__=='__main__': main()
