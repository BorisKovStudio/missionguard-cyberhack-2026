"""Public fictional data only; fixed reviewed source may be used as an SDL command."""
import json
import socketserver
import threading
import time
from missionguard.adapters import SyntheticAdapter
from missionguard.policy import FIELDS, canonical, closed, integer, require, unique_strings

FIXTURE = SyntheticAdapter()
MAX_BODY = 4096
MAX_RESPONSE = 16384

def select(payload):
    closed(payload, {'operation', 'arguments'})
    operation = payload['operation']; require(type(operation) is str and operation in FIELDS)
    args = payload['arguments']; closed(args, {'event_ids', 'fields', 'limit'})
    unique_strings(args['event_ids']); unique_strings(args['fields']); integer(args['limit'], 1, 3)
    require(len(args['event_ids']) <= 3 and set(args['event_ids']) <= {'evt-ai', 'evt-security', 'evt-design'})
    require(set(args['fields']) <= FIELDS[operation])
    if operation != 'events.list': require(len(args['event_ids']) == 1 and args['limit'] == 1)
    source = FIXTURE.analyses if operation == 'analyses.get' else FIXTURE.events
    rows = [{k: row[k] for k in set(args['fields']) | {'event_id'} if k in row}
            for row in source if row['event_id'] in args['event_ids']][:args['limit']]
    return {'mode': 'public_synthetic_fixture', 'source': 'akash_public_dataset', 'rows': rows}

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        deadline = time.monotonic() + 5; data = bytearray()
        def receive():
            remaining = deadline - time.monotonic(); require(remaining > 0)
            self.request.settimeout(remaining); part = self.request.recv(1024); require(part)
            return part
        try:
            while b'\r\n\r\n' not in data:
                data.extend(receive()); require(len(data) <= 8192)
            head, body = bytes(data).split(b'\r\n\r\n', 1); require(len(head) <= 4096)
            lines = head.split(b'\r\n'); require(lines[0] == b'POST /v1/read HTTP/1.1' and len(lines) <= 17)
            headers = {}
            for line in lines[1:]:
                require(b':' in line); key, value = line.split(b':', 1); key = key.lower(); value = value.strip()
                require(key not in headers and key in {b'host', b'content-type', b'content-length', b'accept', b'connection', b'accept-encoding', b'user-agent'})
                require(value and all(32 <= c <= 126 for c in value)); headers[key] = value
            require(headers.get(b'content-type') == b'application/json')
            length = headers.get(b'content-length', b''); require(length.isdigit() and 1 <= int(length) <= MAX_BODY)
            length = int(length); require(len(body) <= length)
            while len(body) < length: body += receive(); require(len(body) <= length)
            from missionguard.policy import strict_loads
            raw = canonical(select(strict_loads(body.decode('utf-8')))).encode(); require(len(raw) <= MAX_RESPONSE)
            remaining = deadline - time.monotonic(); require(remaining > 0); self.request.settimeout(remaining)
            self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: ' + str(len(raw)).encode() + b'\r\n\r\n' + raw)
        except Exception:
            pass

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 8
    def __init__(self, address):
        self.slots = threading.BoundedSemaphore(8); super().__init__(address, Handler)
    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False): request.close(); return
        try: super().process_request(request, address)
        except BaseException: self.slots.release(); raise
    def process_request_thread(self, request, address):
        try: super().process_request_thread(request, address)
        finally: self.slots.release()
    def handle_error(self, request, address): pass

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--serve-reviewed-public-dataset', action='store_true')
    args = parser.parse_args()
    if args.serve_reviewed_public_dataset:
        with Server(('0.0.0.0', 8080)) as server: server.serve_forever()
    else: parser.print_help()
