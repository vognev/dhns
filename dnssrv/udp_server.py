import socket, traceback, time
from dnslib import DNSRecord
from multiplexer.server import Server as BaseServer
from dnssrv import Handler
from cachetools import LRUCache


class UdpServer(BaseServer):
    def __init__(self, addr, handler: Handler):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(addr)
        self._handler = handler
        self._queue = []
        self._cache = LRUCache(64000)

    def read(self):
        buf, addr = self._sock.recvfrom(512)
        try:
            query = DNSRecord.parse(buf)
            print("DNS Q %s FROM: %s:%d" % (query.q.qname, addr[0], addr[1]))

            key = "%s/%d" % (query.q.qname, query.q.qclass)
            now = time.time()

            answer = None

            if key in self._cache:
                received, cached = self._cache[key]
                try:
                    answer = query.reply()
                    for rr in cached.rr:
                        rr.ttl -= int(now - received)
                        answer.add_answer(rr)
                    self._cache[key] = (now, cached)
                except:
                    answer = None

            if answer is None:
                answer = self._handler.handle(query)
                if len(answer.rr):
                    self._cache[key] = (time.time(), answer)

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
