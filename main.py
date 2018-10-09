from dnssrv.middlewares import DockerHandler, GoogleDnsHandler, FixHandler
from dhcpsrv.middlewares import MemoryPool
from dnslib import QTYPE
import dhns, logging
logging.basicConfig(level = logging.INFO, format='%(asctime)s %(message)s')

server = dhns.DhcpNameserver()

server.push(DockerHandler(
    docker = 'unix:///var/run/docker.sock',
    domain = 'docker',
))

server.push(FixHandler([
    ('cluster.kvm', QTYPE.A, '10.3.2.2'),
    ('cluster.kvm', QTYPE.A, '10.3.2.3'),
    ('cluster.kvm', QTYPE.A, '10.3.2.4')
]))

server.push(MemoryPool(
    address='10.3.2.1',
    netmask='255.255.255.0',
    gateway='10.3.2.1',
    nameservers=['10.3.2.1'],
    domain=b'kvm',
    entries={
        '5254009FCCD0': {'address': '10.3.2.2', 'hostname': 'node01'},
        '5254009B1CA3': {'address': '10.3.2.3', 'hostname': 'node02'},
        '525400E9076F': {'address': '10.3.2.3', 'hostname': 'node03'},
    }
))

server.fallback(GoogleDnsHandler())

try:
    server.start()
except KeyboardInterrupt:
    server.stop()


