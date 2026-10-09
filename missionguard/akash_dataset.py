"""Trusted host-only fixed provider endpoint; public fixture pin, no credentials."""
import hashlib
import socket
import threading
import time
from deploy.akash import owner_bootstrap_client as transport
from .policy import canonical, require, strict_loads
from .public_dataset import select, MAX_RESPONSE

HOST = 'provider.zencloud.eu'

class AkashDatasetAdapter:
    environment = 'synthetic_lab'
    connection_ref = 'akash-public-fixture-v1'
    bounded = True
    result_source = 'akash_public_synthetic_http'
    def __init__(self, port):
        require(type(port) is int and 1 <= port <= 65535)
        self.port = port; self.dispatch_count = 0; self._lock = threading.Lock()
    def invoke(self, operation, arguments, *, max_rows, max_bytes):
        require(type(max_rows) is int and max_rows == arguments['limit'] and max_rows <= 3)
        payload = {'operation': operation, 'arguments': arguments}
        expected = canonical(select(payload)).encode(); require(len(expected) <= min(max_bytes, MAX_RESPONSE))
        body = canonical(payload).encode(); require(len(body) <= 4096)
        deadline = transport.Deadline(); deadline.until = time.monotonic() + 5
        v = transport.helper(); v.HOST = HOST
        with self._lock: self.dispatch_count += 1
        family, kind, protocol, address = v.resolve(deadline)
        address = (address[0], self.port, *address[2:]); connection = socket.socket(family, kind, protocol)
        try:
            connection.settimeout(deadline.remaining()); connection.connect(address)
            raw = ('POST /v1/read HTTP/1.1\r\nHost: '+HOST+':'+str(self.port)+'\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: '+str(len(body))+'\r\n\r\n').encode()+body
            connection.settimeout(deadline.remaining()); connection.sendall(raw)
            code, headers, received = v.read_response(connection, deadline, MAX_RESPONSE)
            require(code == 200 and headers.get('content-type') == 'application/json'
                    and not set(headers) & {'location', 'content-encoding', 'transfer-encoding'})
            require(hashlib.sha256(received).digest() == hashlib.sha256(expected).digest())
            return strict_loads(received.decode('utf-8'))['rows']
        finally: connection.close()
