# -*- coding: utf-8 -*-

from setuptools import setup, Extension

setup(name="nettle",
      version="1.0",
      description='Python bindings to the nettle cryptographic library',
      author='Henrik Rindlöw',
      author_email='henrik@rindlow.se',
      url='https://github.com/rindlow/python-nettle',
      license='GPLv2',
      test_suite='tests',
      packages=['nettle'],
      ext_modules=[
          Extension("_nettle", libraries=['nettle', 'hogweed', 'gmp'],
                    sources=['src/nettle_hashes.c',
                             'src/nettle_ciphers.c',
                             'src/nettle_macs.c',
                             'src/nettle_pubkey.c',
                             'src/nettle_asn1.c',
                             'src/nettle.c'])])
