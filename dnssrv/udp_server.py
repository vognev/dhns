import socket, traceback
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

    def read(self):
        buf, addr = self._sock.recvfrom(512)
        try:
            query = DNSRecord.parse(buf)
            answer = self._handler.handle(query)
            self._queue.append((addr, answer))
        except Exception as e:
            traceback.print_exc()

    def write(self):
        if len(self._queue):
            tup = self._queue.pop(0)
            self._sock.sendto(tup[1].pack(), tup[0])

    def wqlen(self):
        return len(self._queue)

    def fileno(self):
        return self._sock.fileno()
