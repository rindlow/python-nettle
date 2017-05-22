from distutils.core import setup, Extension
setup(name="nettle",
      version="3.3",
      description='Python bindings to the nettle cryptographic library',
      author='Henrik Rindlöw',
      author_email='henrik@rindlow.se',
      packages=['nettle'],
      ext_modules=[
          Extension("nettle.hash", libraries=['nettle'],
                    sources=['nettle_hash.c'])])

