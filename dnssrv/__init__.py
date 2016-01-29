from dnslib import DNSRecord, RCODE
from dnssrv.middlewares import Middleware


PRIO_HIGHEST = 100
PRIO_NORMAL = 50
PRIO_LOWEST = 0


class Handler:
    def __init__(self):
        self.middleware = []

    def add_middleware(self, middleware: Middleware, priority = PRIO_NORMAL):
        self.middleware.append((middleware, priority))
        self._sort()

    def handle(self, query: DNSRecord):
        answer = query.reply()

        for middleware in self.middleware:
            if middleware[0].handle_dns_packet(query, answer):
                break

        return answer

    def _sort(self):
        self.middleware.sort(key=lambda tup: tup[1], reverse=True)
