import os
from setuptools import setup

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
  name='dhns',
  version='0.0.1',
  install_requires=['dnslib == 0.9.6', 'cachetools == 1.1.5', 'docker-py'],
  scripts=['main.py'],
  packages=['dhcplib', 'dhcpsrv', 'dhns', 'dnssrv', 'multiplexer']
)
