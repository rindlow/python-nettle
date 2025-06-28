# -*- coding: utf-8 -*-

from setuptools import setup, Extension

setup(name="nettle",
      packages=['nettle'],
      ext_modules=[
          Extension("_nettle", libraries=['nettle', 'hogweed', 'gmp'],
                    include_dirs=['/opt/homebrew/include', './src'],
                    library_dirs=['/opt/homebrew/lib'],
                    sources=['src/nettle_hashes.c',
                             'src/nettle_ciphers.c',
                             'src/nettle_macs.c',
                             'src/nettle_pubkey.c',
                             'src/nettle_asn1.c',
                             'src/nettle.c'],
                    extra_compile_args=['-Werror'])])
