from dnslib import RR, DNSRecord, RDMAP, QTYPE
from os import getenv


class Middleware:
    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        raise NotImplemented


class Handler:
    def __init__(self):
        self.middleware = []

    def add_middleware(self, middleware: Middleware, priority):
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


class SrvHandler(Middleware):
    def __init__(self, glob='*', address=None, port=53):
        self.glob = glob
        self.address = address
        self.port = port

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        if query.q.qname.matchGlob(self.glob):
            try:
                local_a = DNSRecord.parse(query.send(self.address, port=self.port, timeout=1.0))
                for rr in local_a.rr:
                    answer.add_answer(rr)
                return True
            except:
                pass
            finally:
                return True


class FixHandler(Middleware):
    def __init__(self, records):
        self.records = records

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        import random

        qname = query.q.qname
        qtype = query.q.qtype
        found = False

        records = []

        for rec in self.records:
            if qname.matchGlob(rec[0]):
                found = True
                if qtype == QTYPE.A and rec[1] == QTYPE.CNAME:
                    # self-resolve it as A additionally
                    local_q = DNSRecord.question(rec[2], "A")
                    local_a = DNSRecord.parse(local_q.send('localhost', port=int(getenv("DNSPORT", 5353)), timeout=1.0))

                    for rr in local_a.rr:
                        records.append((
                            qname,
                            rr.rtype,
                            str(rr.rdata)
                        ))

                    # records.append((qname, rec[1], rec[2]))
                if qtype == QTYPE.ANY:
                    records.append(rec)
                elif qtype == rec[1]:
                    records.append(rec)

        random.shuffle(records)

        for rec in records:
            answer.add_answer(RR(rname=rec[0], rtype=rec[1], ttl=60, rdata=RDMAP.get(QTYPE.get(rec[1]))(rec[2])))

        return found
