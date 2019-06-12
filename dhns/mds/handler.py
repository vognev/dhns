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
            "    sudo:",
            "    - ALL=(ALL) NOPASSWD:ALL",
        ]).encode('ascii'))

    def do_handle_instance_id(self):
        client_host, _ = self.client_address
        iid = "i-%s" % client_host

        self.send_response(200)
        self.end_headers()
        self.wfile.write(iid.encode('ascii'))

    def do_handle_local_hostname(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write("localhost".encode('ascii'))

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
