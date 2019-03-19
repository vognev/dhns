from setuptools import setup, find_packages

setup(
  name='dhns',
  version='0.0.1',
  install_requires=['dnslib', 'cachetools', 'docker'],
  scripts=['main.py'],
  packages=find_packages()
)
