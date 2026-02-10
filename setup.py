from setuptools import Extension, setup

setup(name="nettle",
      packages=['nettle'],
      ext_modules=[
          Extension("_nettle", libraries=['nettle', 'hogweed', 'gmp'],
                    include_dirs=['/usr/local/include', './src'],
                    library_dirs=['/usr/local/lib'],
                    sources=['src/nettle_hashes.c',
                             'src/nettle_ciphers.c',
                             'src/nettle_macs.c',
                             'src/nettle_random.c',
                             'src/nettle_pubkey.c',
                             'src/nettle_asn1.c',
                             'src/nettle.c'],
                    extra_compile_args=['-Werror'])])
