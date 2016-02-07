from dnslib import RR, DNSRecord, RDMAP, QTYPE
from resolvconf import get_system_resolvers


class Middleware:
    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        raise NotImplemented


class SrvHandler(Middleware):
    def __init__(self, suffix=None, address=None, port=53):
        self.suffix = suffix
        self.address = address
        self.port = port

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        if query.q.qname.matchSuffix(self.suffix):
            try:
                local_a = DNSRecord.parse(query.send(self.address, port=self.port))
                for rr in local_a.rr:
                    answer.add_answer(rr)
                return True
            except:
                pass
            finally:
                return True


class SysHandler(Middleware):
    def __init__(self):
        self.resolvers = []
        for addr in get_system_resolvers():
            self.resolvers.append((addr, 53))

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        for resolver in self.resolvers:
            try:
                local_a = DNSRecord.parse(query.send(resolver[0], resolver[1]))
                for rr in local_a.rr:
                    answer.add_answer(rr)
                return True
            except:
                pass


class FixHandler(Middleware):
    def __init__(self, records):
        self.records = records

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        qname = query.q.qname
        qtype = query.q.qtype
        found = False

        for rec in self.records:
            if qname == rec[0]:
                found = True
                if qtype == QTYPE.ANY:
                    answer.add_answer(RR(rname=rec[0], rtype=rec[1], ttl=60, rdata=RDMAP.get(QTYPE.get(rec[1]))(rec[2])))
                elif qtype == rec[1]:
                    answer.add_answer(RR(rname=rec[0], rtype=rec[1], ttl=60, rdata=RDMAP.get(QTYPE.get(rec[1]))(rec[2])))
                    break
        return found
