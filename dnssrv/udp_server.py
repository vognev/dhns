import socket, traceback, threading, logging
from dnslib import DNSRecord
from multiplexer.server import Server as BaseServer
from dnssrv import Handler


class UdpServer(BaseServer):
    def __init__(self, addr, handler: Handler):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(addr)
        self._handler = handler
        self._queue = []
        self._lock = threading.Lock()

    def read(self):
        #self.process()
        thread = threading.Thread(group=None, target=self.process)
        thread.start()

    def write(self):
        if len(self._queue):
            tup = self._queue.pop(0)
            self._sock.sendto(tup[1].pack(), tup[0])

    def wqlen(self):
        return len(self._queue)

    def fileno(self):
        return self._sock.fileno()

    def process(self):
        with self._lock:
            buf, addr = self._sock.recvfrom(512)
        try:
            query = DNSRecord.parse(buf)
            logging.info("DNS Q %s FROM: %s:%d" % (query.q.qname, addr[0], addr[1]))
            answer = self._handler.handle(query)
            with self._lock:
                self._queue.append((addr, answer))
        except Exception as e:
            traceback.print_exc()
