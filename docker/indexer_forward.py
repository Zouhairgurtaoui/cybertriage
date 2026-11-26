"""Container-local TCP forwarding; Indexer TLS stays end-to-end and verified."""

from contextlib import nullcontext
import logging
import os
import re
import select
import socket
import socketserver
from threading import BoundedSemaphore, Event, Thread
import time
from urllib.parse import urlsplit


logger = logging.getLogger(__name__)


class IndexerForward:
    def __init__(self, address: tuple[str, int], upstream: tuple[str, int]):
        self.address, self.upstream = address, upstream
        self.stop = Event()
        self.capacity = BoundedSemaphore(16)
        self.server = None
        self.thread = None

    def __enter__(self):
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                with socket.create_connection(owner.upstream, timeout=5) as upstream:
                    client = self.request
                    client.settimeout(5)
                    upstream.settimeout(5)
                    readers = [client, upstream]
                    peers = {client: upstream, upstream: client}
                    activity = time.monotonic()
                    while readers and not owner.stop.is_set():
                        ready, _, _ = select.select(readers, [], [], 1)
                        if not ready:
                            if time.monotonic() - activity > 90:
                                return
                            continue
                        for source in ready:
                            body = source.recv(65536)
                            target = peers[source]
                            if body:
                                target.sendall(body)
                                activity = time.monotonic()
                            else:
                                readers.remove(source)
                                try:
                                    target.shutdown(socket.SHUT_WR)
                                except OSError:
                                    pass

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

            def verify_request(self, request, client_address):
                return owner.capacity.acquire(blocking=False)

            def process_request_thread(self, request, client_address):
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    owner.capacity.release()

            def handle_error(self, request, client_address):
                # No credentials or forwarded bytes are decoded or logged.
                logger.warning("Indexer TCP forward connection failed; the caller receives a transport error.")

        self.server = Server(self.address, Handler)
        self.thread = Thread(target=self.server.serve_forever, name="indexer-forward", daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_exception):
        self.stop.set()
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=3)


def configured_indexer_forward():
    host = os.environ.get("CYBERTRIAGE_INDEXER_FORWARD_HOST", "")
    port = os.environ.get("CYBERTRIAGE_INDEXER_FORWARD_PORT", "")
    if not host and not port:
        return nullcontext()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host) or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("Configure a valid Indexer forward host and port together.")
    endpoint = urlsplit(os.environ.get("CYBERTRIAGE_INDEXER_URL", ""))
    if (endpoint.scheme != "https" or endpoint.hostname != "127.0.0.1"
            or endpoint.username is not None or endpoint.password is not None
            or endpoint.path not in {"", "/"} or endpoint.query or endpoint.fragment
            or endpoint.port is None or not 1024 <= endpoint.port <= 65535):
        raise ValueError("A container Indexer forward requires an explicit HTTPS 127.0.0.1 origin on an unprivileged port.")
    return IndexerForward(("127.0.0.1", endpoint.port), (host, int(port)))
