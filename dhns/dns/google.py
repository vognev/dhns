from dnslib import DNSRecord
from cachetools import LRUCache
from dhns.dns import Middleware
import time, traceback


class Resolver(Middleware):
    def __init__(self):
        self.resolvers = [
            ("8.8.8.8", 53),
            ("8.8.4.4", 53)
        ]
        self.cache = LRUCache(64000)

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        key = "%s/%d/%d" % (query.q.qname, query.q.qclass, query.q.qtype)

        if key in self.cache:
            received, cached = self.cache[key]
            if not self.is_expired(received, cached):
                return self.from_cache(key, answer)

        for resolver in self.resolvers:
            try:
                res = DNSRecord.parse(query.send(resolver[0], resolver[1], timeout=5))
                if 0 == len(res.rr) or res.header.rcode:
                    return self.from_res(res, answer)
                else:
                    self.cache[key] = (time.time(), res)
                    return self.from_cache(key, answer)
            except:
                traceback.print_exc()

    def is_expired(self, cached, answer):
        now = time.time()
        for rr in answer.rr:
            if cached + rr.ttl < now:
                return True
        return False

    def from_cache(self, key, answer):
        now = time.time(); cached, res = self.cache[key]
        for rr in res.rr:
            rr.ttl -= int(now - cached)
            answer.add_answer(rr)
        answer.header.rcode = res.header.rcode
        return True

    def from_res(self, res, answer):
        for rr in res.rr:
            answer.add_answer(rr)
        answer.header.rcode = res.header.rcode
        return True
