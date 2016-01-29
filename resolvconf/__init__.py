from os import path


RESOLVCONF = '/etc/resolv.conf'


def get_system_resolvers():
    resolvers = []
    if path.isfile(RESOLVCONF):
        for line in open(RESOLVCONF):
            if 'nameserver' in line:
                resolvers.append(line.split(' ')[1].strip())

    for resolver in resolvers:
        # todo: skip any link-local/loopback addresses
        # todo: resolve names
        # todo: windows
        # todo: google fallback
        if 'localhost' == resolver or '127.0.0.1' == resolver:
            resolvers.remove(resolver)

    return resolvers
