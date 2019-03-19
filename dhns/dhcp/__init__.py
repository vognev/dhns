from dhns.dhcp.proto.packet import Packet


class Middleware:
    def handle_dhcp_packet(self, interface, query: Packet, answer: Packet):
        raise NotImplemented


class Handler:
    def __init__(self):
        self.middleware = []

    def add_middleware(self, middleware: Middleware, priority):
        self.middleware.append((middleware, priority))
        self._sort()

    def handle(self, interface, query: Packet):
        answer = query.reply()

        for middleware in self.middleware:
            if middleware[0].handle_dhcp_packet(interface, query, answer):
                return answer, middleware[0]

        return answer, None

    def _sort(self):
        self.middleware.sort(key=lambda tup: tup[1], reverse=True)
