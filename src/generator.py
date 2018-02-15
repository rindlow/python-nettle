#!/usr/bin/env python3

# generator.py
#
# Copyright (C) 2017, 2018 Henrik Rindlöw
#
# This file is part of python-nettle.
#
# Python-nettle is free software: you can redistribute it and/or
# modify it under the terms of either:
#
#   * the GNU Lesser General Public License as published by the Free
#     Software Foundation; either version 3 of the License, or (at your
#     option) any later version.
#
# or
#
#   * the GNU General Public License as published by the Free
#     Software Foundation; either version 2 of the License, or (at your
#     option) any later version.
#
# or both in parallel, as here.
#
# Python-nettle is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received copies of the GNU General Public License and
# the GNU Lesser General Public License along with this program.  If
# not, see http://www.gnu.org/licenses/.

from CModule import CModule
from CException import CException
from Hash import Hash
from Cipher import Cipher
from CipherMode import CipherMode
from MAC import MAC
from PubKey import Yarrow, RSAKeyPair, RSAPubKey
import docstrings

hashes = [
    {'name': 'sha1', 'headers': ['sha1.h'],
     'docstring': 'SHA1 is a hash function specified by NIST (The U.S.'
     ' National Institute for Standards and Technology).'},
    {'name': 'sha224', 'headers': ['sha2.h'],
     'docstring': 'SHA224 is a variant of SHA256, with a different initial'
     ' state, and with the output truncated to 224 bits, or 28 octets.'},
    {'name': 'sha256', 'headers': ['sha2.h'],
     'docstring': 'SHA256 is a member of the SHA2 family. It outputs hash'
     ' values of 256 bits, or 32 octets.'}
]

ciphers = [
    {'name': 'arcfour', 'family': None, 'headers': ['arcfour.h'],
     'docstring': docstrings.aesdocs, 'lenparam': True, 'twokeys': False,
     'twofuncs': False, 'invert': False, 'variable_keylen': False},
    {'name': 'aes128', 'family': 'aes', 'headers': ['aes.h'],
     'lenparam': False, 'docstring': docstrings.aesdocs,
     'twokeys': True, 'twofuncs': True, 'invert': True,
     'variable_keylen': False},
    {'name': 'aes192', 'family': 'aes', 'headers': ['aes.h'],
     'lenparam': False, 'docstring': docstrings.aesdocs,
     'twokeys': True, 'twofuncs': True, 'invert': True, 
     'variable_keylen': False},
    {'name': 'aes256', 'family': 'aes', 'headers': ['aes.h'],
     'lenparam': False, 'docstring': docstrings.aesdocs,
     'twokeys': True, 'twofuncs': True, 'invert': True,
     'variable_keylen': False},
    {'name': 'camellia128', 'family': 'camellia',
     'headers': ['camellia.h'],
     'lenparam': False, 'twokeys': True,
     'twofuncs': False, 'invert': True, 'docstring': docstrings.camelliadocs,
     'variable_keylen': False},
    {'name': 'camellia192', 'family': 'camellia',
     'headers': ['camellia.h'],
     'lenparam': False, 'twokeys': True,
     'twofuncs': False, 'invert': True, 'docstring': docstrings.camelliadocs,
     'variable_keylen': False},
    {'name': 'camellia256', 'family': 'camellia',
     'headers': ['camellia.h'],
     'lenparam': False, 'twokeys': True,
     'twofuncs': False, 'invert': True, 'docstring': docstrings.camelliadocs,
     'variable_keylen': False},
    {'name': 'serpent', 'family': 'serpent',
     'headers': ['serpent.h'], 'lenparam': True, 'twokeys': False,
     'twofuncs': True, 'invert': False, 'docstring': docstrings.serpentdocs,
     'variable_keylen': True},
    {'name': 'twofish', 'family': 'twofish',
     'headers': ['twofish.h'], 'lenparam': True, 'twokeys': False,
     'twofuncs': True, 'invert': False, 'docstring': docstrings.twofishdocs,
     'variable_keylen': True},
]

ciphermodes = [
    {'name': 'CBC', 'docstring': 'Cipher Block Chaining',
     'headers': ['cbc.h']},
    {'name': 'CTR', 'docstring': 'Counter Mode',
     'headers': ['ctr.h']},
    {'name': 'GCM', 'docstring': 'Galois Counter Mode',
     'headers': ['gcm.h']},
    ]

macs = [
    {'name': 'hmac_sha1', 'headers': ['hmac.h'],
     'docstring': docstrings.hmacdocs},
    {'name': 'hmac_sha256', 'headers': ['hmac.h'],
     'docstring': docstrings.hmacdocs},
    {'name': 'umac128', 'headers': ['umac.h'],
     'docstring': docstrings.umacdocs},
]

exceptions = [
    {'name': 'BaseException', 'base': 'NULL',
     'docs': 'Generic Nettle Exception'},
    {'name': 'KeyLenError', 'base': 'BaseException',
     'docs': 'Key Length is not as expected'},
    {'name': 'NotInitializedError', 'base': 'BaseException',
     'docs': 'Object must be initialized before calling this method'},
    {'name': 'RandomError', 'base': 'BaseException',
     'docs': 'Failed to open/read /dev/random'},
    {'name': 'RSAError', 'base': 'BaseException',
     'docs': 'RSA operation failed'},
    {'name': 'ASN1Error', 'base': 'BaseException',
     'docs': 'ASN1 parsing failed'},
]


class Generator:
    cipher_file = 'nettle_ciphers.c'
    hash_file = 'nettle_hashes.c'
    header_file = 'nettle.h'
    mac_file = 'nettle_macs.c'
    mod_file = 'nettle.c'
    pubkey_file = 'nettle_pubkey.c'
    python_module = '../nettle/autogen.py'

    def __init__(self):
        self.objects = []

    def write_python2_buffer_struct(self, f):
        f.write('#if PY_MAJOR_VERSION < 3\n'
                'typedef struct py2buf_struct\n{\n'
                '  const uint8_t *buf;\n'
                '  int len;\n'
                '} nettle_py2buf;\n'
                '#endif\n')

    def gen_hash_file(self, hashdata):
        with open(self.hash_file, 'w') as f:
            f.write('#include <Python.h>\n')
            f.write('#include <structmember.h>\n')
            f.write('#include "{}"\n'.format(self.header_file))
            headers = set()
            for h in hashdata:
                headers.update(set(h['headers']))
            for header in sorted(headers):
                f.write('#include <nettle/{}>\n'.format(header))
            self.write_python2_buffer_struct(f)
            f.write('\n')

            for h in hashes:
                hashclass = Hash(h['name'], h['docstring'])
                hashclass.write_to_file(f)
                self.objects.append(hashclass)

    def gen_cipher_file(self, cipherdata, modedata):
        with open(self.cipher_file, 'w') as f:
            f.write('#include <Python.h>\n')
            f.write('#include <structmember.h>\n')
            f.write('#include "{}"\n'.format(self.header_file))
            headers = set()
            for c in cipherdata:
                headers.update(set(c['headers']))
            for m in modedata:
                headers.update(set(m['headers']))
            for header in sorted(headers):
                f.write('#include <nettle/{}>\n'.format(header))
            self.write_python2_buffer_struct(f)
            f.write('\n')
            for c in cipherdata:
                cipherclass = Cipher(c['name'],
                                     family=c['family'],
                                     docs=c['docstring'],
                                     lenparam=c['lenparam'],
                                     twokeys=c['twokeys'],
                                     twofuncs=c['twofuncs'],
                                     invert=c['invert'],
                                     varkey=c['variable_keylen'])
                cipherclass.write_to_file(f)
                self.objects.append(cipherclass)
            for m in modedata:
                mode = CipherMode(m['name'], m['docstring'],
                                  [c for c in cipherdata
                                   if c['family'] == 'aes'])
                mode.write_to_file(f)
                self.objects.append(mode)

    def gen_mac_file(self, macdata):
        with open(self.mac_file, 'w') as f:
            f.write('#include <Python.h>\n')
            f.write('#include <structmember.h>\n')
            f.write('#include "{}"\n'.format(self.header_file))
            headers = set()
            for m in macdata:
                headers.update(set(m['headers']))
            for header in sorted(headers):
                f.write('#include <nettle/{}>\n'.format(header))
            self.write_python2_buffer_struct(f)
            f.write('\n')

            for m in macdata:
                macclass = MAC(m['name'], m['docstring'])
                macclass.write_to_file(f)
                self.objects.append(macclass)

    def gen_pubkey_file(self):
        with open(self.pubkey_file, 'w') as f:
            f.write('#include <Python.h>\n')
            f.write('#include <structmember.h>\n')
            f.write('#include <fcntl.h>\n')
            f.write('#include <nettle/yarrow.h>\n')
            f.write('#include <nettle/rsa.h>\n')
            f.write('#include "nettle_asn1.h"\n')
            f.write('#include "{}"\n'.format(self.header_file))
            self.write_python2_buffer_struct(f)
            for cls in [Yarrow(), RSAPubKey(), RSAKeyPair()]:
                cls.write_to_file(f)
                self.objects.append(cls)

    def gen_exceptions(self, exceptions):
        for e in exceptions:
            self.objects.append(CException(e['name'], 'nettle',
                                           e['docs'], e['base']))

    def gen_header_file(self):
        with open(self.header_file, 'w') as f:
            f.write('#ifndef _NETTLE_H_\n#define _NETTLE_H_\n\n')
            f.write('#include <nettle/aes.h>\n')
            f.write('#include <nettle/camellia.h>\n')
            f.write('#include <nettle/sha2.h>\n')
            for object in self.objects:
                object.write_decl_to_file(f, extern=True)
            f.write('#endif /* _NETTLE_H_ */\n')

    def gen_mod_file(self):
        with open(self.mod_file, 'w') as f:
            f.write('#include <Python.h>\n')
            f.write('#include "{}"\n'.format(self.header_file))
            for object in sorted(self.objects, key=lambda o: o.name):
                object.write_decl_to_file(f, extern=False)

            module = CModule(name='_nettle', objects=self.objects,
                             doc='An interface to the Nettle'
                             ' low level cryptographic library')
            module.write_to_file(f)

    def gen_python_file(self):
        with open(self.python_module, 'w') as f:
            f.write('import _nettle\n')
            for object in sorted(self.objects, key=lambda o: o.name):
                object.write_python_subclass(f)


gen = Generator()
gen.gen_hash_file(hashes)
gen.gen_cipher_file(ciphers, ciphermodes)
gen.gen_mac_file(macs)
gen.gen_pubkey_file()
gen.gen_exceptions(exceptions)
gen.gen_header_file()
gen.gen_mod_file()
gen.gen_python_file()
