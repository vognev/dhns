from http.server import BaseHTTPRequestHandler
import logging


class Handler(BaseHTTPRequestHandler):
    def __init__(self, conn, addr, opts):
        self.opts = opts
        BaseHTTPRequestHandler.__init__(self, conn, addr, self)

    def do_GET(self):
        if self.path == "/":
            self.do_handle_root()
        elif self.path == "/2009-04-04/meta-data/instance-id":
            self.do_handle_instance_id()
        elif self.path == "/2009-04-04/meta-data/local-hostname":
            self.do_handle_local_hostname()
        elif self.path == "/2009-04-04/user-data":
            self.do_handle_user_data()
        elif self.path.startswith("/2009-04-04/meta-data/public-keys"):
            self.do_list_public_keys()
        elif self.path.startswith("/2009-04-04/meta-data"):
            self.do_handle_meta_data()
        else:
            logging.info(self.path)
            self.send_response(400)
            self.end_headers()

    def do_handle_meta_data(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write('\n'.join([
            "instance-id",
            "local-hostname",
            "public-keys",
        ]).encode('ascii'))

    def do_handle_user_data(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write('\n'.join([
            "#cloud-config",
            "users:",
            "  - default",
            "  - name: node",
            "    groups: users",
            "    sudo: ALL=(ALL) NOPASSWD:ALL",
        ]).encode('ascii'))

    def do_handle_instance_id(self):
        client_address, _ = self.client_address
        domain = self.get_dom_by_ip(client_address)

        if domain is None:
            instance_id = "vm-%s" % client_address
        else:
            instance_id = "vm-%s" % domain.name()

        self.send_response(200)
        self.end_headers()
        self.wfile.write(instance_id.encode('ascii'))

    def do_handle_local_hostname(self):
        client_address, _ = self.client_address
        domain = self.get_dom_by_ip(client_address)

        if domain is None:
            local_hostname = "localhost"
        else:
            local_hostname = domain.name()

        self.send_response(200)
        self.end_headers()
        self.wfile.write(local_hostname.encode('ascii'))

    def do_list_public_keys(self):
        self.send_response(200)
        self.end_headers()

        self.wfile.write('\n'.join(
            [ ("%s" % key) for key in self.opts['public_keys']]
        ).encode('ascii'))

    def do_handle_root(self):
        self.send_response(200)
        self.end_headers()

        self.wfile.write('\n'.join([
            "2009-04-04"
        ]).encode('ascii'))

    @staticmethod
    def get_arp_table():
        table = list()

        with open('/proc/net/arp', 'r') as fh:
            fh.readline()
            for line in fh:
                props = line.strip().split()
                table.append({'ip': props[0], 'mac': props[3], 'dev': props[5]})

        return table

    @staticmethod
    def get_dom_by_ip(client_address):
        try:
            arp = next(obj for obj in Handler.get_arp_table() if obj['ip'] == client_address)
        except StopIteration:
            return None

        try:
            import libvirt
            import xml.etree.ElementTree as ET

            with libvirt.open('qemu:///system') as conn:
                domains = conn.listAllDomains(libvirt.VIR_CONNECT_LIST_DOMAINS_ACTIVE)
                for domain in domains:
                    root = ET.fromstring(domain.XMLDesc(0))
                    searchString = "./devices/interface/mac[@address='{0}']".format(arp['mac'])
                    if (root.find(searchString) is not None):
                        return domain
        except ModuleNotFoundError:
            return None
