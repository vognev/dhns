from setuptools import setup

setup(
  name='dhns',
  version='0.0.1',
  install_requires=['dnslib == 0.9.6', 'cachetools == 1.1.5', 'docker-py'],
  scripts=['main.py'],
  packages=['dhcplib', 'dhcpsrv', 'dhns', 'dnssrv', 'multiplexer', 'resolvconf']
)
