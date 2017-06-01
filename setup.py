# -*- coding: utf-8 -*-

from distutils.core import setup, Extension
setup(name="nettle",
      version="3.3",
      description='Python bindings to the nettle cryptographic library',
      author='Henrik Rindlöw',
      author_email='henrik@rindlow.se',
      ext_modules=[
          Extension("nettle", libraries=['nettle'],
                    sources=['src/nettle_hashes.c',
                             'src/nettle_ciphers.c',
                             'src/nettle.c'])])


