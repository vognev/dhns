from typeguard import typechecked
from collections import namedtuple
from dnslib import DNSLabel, DNSRecord, QTYPE, RR, RDMAP
from dhns.dns import Middleware
import threading, re, json, logging

Container = namedtuple('Container', 'id, name, state, addrs')
RE_VALIDNAME = re.compile('[^\w\d.-]')


def get(d, *keys):
    from functools import reduce
    empty = {}
    return reduce(lambda d, k: d.get(k, empty), keys, d) or None


class Storage:
    def __init__(self):
        self._data = {}
        self._lock = self._lock = threading.Lock()

    @typechecked
    def append(self, key:str, val:list):
        logging.info("+ %s %s" % (key, val))
        with self._lock:
            try:
                self._data[key]['ref'] += 1
                self._data[key]['adr'].extend(val)
            except KeyError:
                self._data[key] = {'ref': 1, 'adr': val}

    @typechecked
    def remove(self, key:str):
        with self._lock:
            try:
                if self._data[key]['ref'] == 1:
                    logging.info("D %s" % key)
                    self._data.pop(key)
                else:
                    logging.info("- %s" % key)
                    self._data[key]['ref'] -= 1
            except KeyError:
                pass
        pass

    @typechecked
    def query(self, key:str) -> list :
        with self._lock:
            try:
                return self._data[key]['adr']
            except KeyError:
                return []


class Resolver(Middleware):
    def __init__(self, docker='unix:///var/run/docker.sock', domain='docker'):
        from docker.client import DockerClient

        self._docker = DockerClient(docker, version='auto')
        self._domain = domain

        self._storage = Storage()
        self._lock = threading.Lock()

        threading.Thread(group=None, target=self.listen).start()

    def listen(self):
        self.running = True

        events = self._docker.events()

        for container in self._docker.containers.list():
            for rec in self._inspect(container):
                self._storage.append(rec.name, rec.addrs)

        for raw in events:
            if not self.running:
                break

            evt = json.loads(raw)
            if evt.get('Type', 'container') != 'container':
                continue

            cid = evt.get('id')
            if cid is None:
                continue

            status = evt.get('status')
            if status in {'start', 'die'}:
                container = self._docker.containers.get(cid)
                for rec in self._inspect(container):
                    if status == 'start':
                        self._storage.append(rec.name, rec.addrs)
                    else:
                        self._storage.remove(rec.name)

    def _inspect(self, container):
        name = get(container.attrs, 'Name')
        if not container.name:
            return None

        id = get(container.attrs, 'Id')
        labels = get(container.attrs, 'Config', 'Labels')
        state = get(container.attrs, 'State', 'Running')

        networks = get(container.attrs, 'NetworkSettings', 'Networks')
        ip_addrs = self._get_addrs(networks)

        return [ Container(id, name, state, ip_addrs) for name in self._get_names(name, labels) ]

    def _get_addrs(self, networks):
        return list(filter(None, [value['IPAddress'] for value in networks.values()]))

    def _get_names(self, name, labels):
        names = [ RE_VALIDNAME.sub('', name).rstrip('.') ]

        labels = labels or {}

        instance = labels.get('com.docker.compose.container-number')
        service = labels.get('com.docker.compose.service')
        project = labels.get('com.docker.compose.project')

        if all((instance, service, project)):
            names.append('%s.%s.%s' % (instance, service, project))
            names.append('%s.%s' % (service, project))

        names = [ '.'.join((name, self._domain)) for name in names ]

        domain = labels.get('com.dhns.domain')
        if domain is not None:
            for name in domain.split(';'):
                names.append(name)

        return names

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        addrs = []

        if query.q.qtype in (QTYPE.A, QTYPE.ANY):
            addrs = self._storage.query(
                str(query.q.qname).rstrip('.')
            )

        if len(addrs):
            for addr in addrs:
                answer.add_answer(
                    RR(rname=query.q.qname, rtype=QTYPE.A, ttl=60, rdata=RDMAP["A"](addr))
                )

            return self

