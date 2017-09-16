import os
from setuptools import setup

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
  name='dhns',
  version='0.0.1',
  install_requires=requirements,
  scripts=['main.py'],
  packages=['dhcplib', 'dhcpsrv', 'dhns', 'dnssrv', 'multiplexer']
)
