# -*- coding: utf-8 -*-

from setuptools import setup, Extension
from unittest import TestLoader

setup(name="nettle",
      version="1.0",
      description='Python bindings to the nettle cryptographic library',
      author='Henrik Rindlöw',
      author_email='henrik@rindlow.se',
      url='https://github.com/rindlow/python-nettle',
      license='GPLv2',
      test_suite='tests',
      ext_modules=[
          Extension("nettle", libraries=['nettle'],
                    sources=['src/nettle_hashes.c',
                             'src/nettle_ciphers.c',
                             'src/nettle.c'])])


