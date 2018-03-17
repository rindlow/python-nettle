#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
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

from collections import defaultdict
from CModule import CModule
from CException import CException
from Hash import Hash
from Cipher import Cipher
from CipherMode import CipherMode
from MAC import MAC
from PubKey import Yarrow, RSAKeyPair, RSAPubKey
import docstrings


def none_factory():
    return lambda: None


hashes = [
    {'name': 'gosthash94', 'headers': ['gosthash94.h'],
     'docstring': docstrings.gosthash94},
    {'name': 'md2', 'headers': ['md2.h'], 'docstring': docstrings.md2},
    {'name': 'md4', 'headers': ['md4.h'], 'docstring': docstrings.md4},
    {'name': 'md5', 'headers': ['md5.h'], 'docstring': docstrings.md5},
    {'name': 'ripemd160', 'headers': ['ripemd160.h'],
     'docstring': docstrings.ripemd160},
    {'name': 'sha1', 'headers': ['sha1.h'], 'docstring': docstrings.sha1},
    {'name': 'sha224', 'headers': ['sha2.h'], 'docstring': docstrings.sha224},
    {'name': 'sha256', 'headers': ['sha2.h'], 'docstring': docstrings.sha256},
    {'name': 'sha512', 'headers': ['sha2.h'], 'docstring': docstrings.sha512},
    {'name': 'sha384', 'headers': ['sha2.h'], 'docstring': docstrings.sha384},
    {'name': 'sha512_224', 'headers': ['sha2.h'],
     'docstring': docstrings.sha384},
    {'name': 'sha512_256', 'headers': ['sha2.h'],
     'docstring': docstrings.sha384},
    {'name': 'sha3_224', 'headers': ['sha3.h'],
     'docstring': docstrings.sha3_224},
    {'name': 'sha3_256', 'headers': ['sha3.h'],
     'docstring': docstrings.sha3_256},
    {'name': 'sha3_384', 'headers': ['sha3.h'],
     'docstring': docstrings.sha3_384},
    {'name': 'sha3_512', 'headers': ['sha3.h'],
     'docstring': docstrings.sha3_512},
]

ciphers = [
    {'name': 'aes128', 'family': 'aes', 'headers': ['aes.h'],
     'docstring': docstrings.aes,
     'twokeys': True, 'twofuncs': True, 'invert': True},
    {'name': 'aes192', 'family': 'aes', 'headers': ['aes.h'],
     'docstring': docstrings.aes,
     'twokeys': True, 'twofuncs': True, 'invert': True},
    {'name': 'aes256', 'family': 'aes', 'headers': ['aes.h'],
     'docstring': docstrings.aes,
     'twokeys': True, 'twofuncs': True, 'invert': True},
    {'name': 'arcfour', 'headers': ['arcfour.h'],
     'docstring': docstrings.arcfour,
     'lenparam': True, 'variable_keylen': True},
    {'name': 'arctwo', 'headers': ['arctwo.h'],
     'docstring': docstrings.arctwo, 'lenparam': True,
     'twofuncs': True, 'variable_keylen': True},
    {'name': 'blowfish', 'family': 'blowfish',
     'headers': ['blowfish.h'],
     'docstring': docstrings.blowfish,
     'lenparam': True, 'twofuncs': True, 'variable_keylen': True},
    {'name': 'camellia128', 'family': 'camellia', 'headers': ['camellia.h'],
     'docstring': docstrings.camellia,
     'twokeys': True, 'invert': True},
    {'name': 'camellia192', 'family': 'camellia', 'headers': ['camellia.h'],
     'docstring': docstrings.camellia,
     'twokeys': True, 'invert': True},
    {'name': 'camellia256', 'family': 'camellia', 'headers': ['camellia.h'],
     'docstring': docstrings.camellia,
     'twokeys': True, 'invert': True},
    {'name': 'cast128', 'family': 'cast128', 'headers': ['cast128.h'],
     'docstring': docstrings.cast128,
     'twofuncs': True},
    {'name': 'chacha', 'headers': ['chacha.h'],
     'docstring': docstrings.chacha,
     'nonce': True},
    {'name': 'des', 'family': 'des', 'headers': ['des.h'],
     'docstring': docstrings.des,
     'twofuncs': True, 'parity': True},
    {'name': 'des3', 'family': 'des', 'headers': ['des.h'],
     'docstring': docstrings.des,
     'twofuncs': True, 'parity': True},
    {'name': 'serpent', 'family': 'serpent', 'headers': ['serpent.h'],
     'docstring': docstrings.serpent,
     'lenparam': True, 'twofuncs': True, 'variable_keylen': True},
    {'name': 'twofish', 'family': 'twofish', 'headers': ['twofish.h'],
     'docstring': docstrings.twofish,
     'lenparam': True, 'twofuncs': True, 'variable_keylen': True},
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
     'docstring': docstrings.hmac},
    {'name': 'hmac_sha256', 'headers': ['hmac.h'],
     'docstring': docstrings.hmac},
    {'name': 'umac128', 'headers': ['umac.h'],
     'docstring': docstrings.umac},
]

exceptions = [
    {'name': 'BaseException', 'base': 'NULL',
     'docs': 'Generic Nettle Exception'},
    {'name': 'KeyLenError', 'base': 'BaseException',
     'docs': 'Key Length is not as expected'},
    {'name': 'DataLenError', 'base': 'BaseException',
     'docs': 'Data length is not a multiple of the block size'},
    {'name': 'NotInitializedError', 'base': 'BaseException',
     'docs': 'Object must be initialized before calling this method'},
    {'name': 'RandomError', 'base': 'BaseException',
     'docs': 'Failed to open/read /dev/random'},
    {'name': 'RSAError', 'base': 'BaseException',
     'docs': 'RSA operation failed'},
    {'name': 'ASN1Error', 'base': 'BaseException',
     'docs': 'ASN1 parsing failed'},
]


# noinspection PyArgumentList
class Generator:
    cipher_file = 'nettle_ciphers.c'
    hash_file = 'nettle_hashes.c'
    header_file = 'nettle.h'
    mac_file = 'nettle_macs.c'
    mod_file = 'nettle.c'
    pubkey_file = 'nettle_pubkey.c'
    python_module = '../nettle/autogen.py'
    cipher_doc_file = '../doc/source/ciphers.rst'
    ciphermode_doc_file = '../doc/source/ciphermodes.rst'
    hash_doc_file = '../doc/source/hashes.rst'
    mac_doc_file = '../doc/source/macs.rst'
    pubkey_doc_file = '../doc/source/pubkey.rst'

    def __init__(self):
        self.objects = []

    @staticmethod
    def write_python2_buffer_struct(f):
        f.write('#if PY_MAJOR_VERSION < 3\n'
                'typedef struct py2buf_struct\n{\n'
                '  const uint8_t *buf;\n'
                '  int len;\n'
                '} nettle_py2buf;\n'
                '#endif\n')

    def gen_hash_file(self, hashdata):
        headers = set(['nettle/' + f for h in hashdata for f in h['headers']])
        classes = [Hash(h['name'], h['docstring']) for h in hashdata]
        self.objects.extend(classes)

        self.write_class_file(self.hash_file, classes, headers)
        self.write_doc_file(self.hash_doc_file, "Hashes",
                            docstrings.hash_example, classes)

    def gen_cipher_file(self, cipherdata, modedata):
        headers = set(['nettle/' + h
                       for m in cipherdata + modedata
                       for h in m['headers']])
        ciphers = [Cipher(defaultdict(none_factory(), c)) for c in cipherdata]
        modes = [CipherMode(m['name'], m['docstring'],
                            [c for c in cipherdata
                             if c.get('family') in ('aes', 'camellia')])
                 for m in modedata]
        classes = ciphers + modes
        self.objects.extend(classes)

        self.write_class_file(self.cipher_file, classes, headers)
        self.write_doc_file(self.cipher_doc_file, "Ciphers",
                            docstrings.cipher_example, ciphers)
        self.write_doc_file(self.ciphermode_doc_file, "Cipher Modes",
                            docstrings.ciphermode_example, modes)

    def gen_mac_file(self, macdata):
        headers = set(['nettle/' + h for m in macdata for h in m['headers']])
        classes = [MAC(m['name'], m['docstring']) for m in macdata]
        self.objects.extend(classes)

        self.write_class_file(self.mac_file, classes, headers)
        self.write_doc_file(self.mac_doc_file, 'Keyed Hash Functions',
                            docstrings.mac_example, classes)

    def gen_pubkey_file(self):
        classes = [Yarrow(), RSAKeyPair(), RSAPubKey()]
        headers = ['fcntl.h', 'nettle/yarrow.h', 'nettle/rsa.h']
        self.objects.extend(classes)

        self.write_class_file(self.pubkey_file, classes, headers,
                              pynettle_headers=['nettle_asn1.h'])

        self.write_doc_file(self.pubkey_doc_file, 'Public Key Encryption',
                            docstrings.pubkey_example, classes)

    def gen_exceptions(self, exceptions):
        for e in exceptions:
            self.objects.append(CException(e['name'], 'nettle',
                                           e['docs'], e['base']))

    def gen_header_file(self):
        with open(self.header_file, 'w') as f:
            f.write('#ifndef _NETTLE_H_\n#define _NETTLE_H_\n\n')
            f.write('#include <nettle/camellia.h>\n')
            f.write('#include <nettle/sha2.h>\n')
            for obj in self.objects:
                obj.write_decl_to_file(f, extern=True)
            f.write('#endif /* _NETTLE_H_ */\n')

    def gen_mod_file(self):
        with open(self.mod_file, 'w') as f:
            f.write('#include <Python.h>\n')
            f.write('#include "{}"\n'.format(self.header_file))
            for obj in sorted(self.objects, key=lambda o: o.name):
                obj.write_decl_to_file(f, extern=False)

            module = CModule(name='_nettle', objects=self.objects,
                             doc='An interface to the Nettle'
                                 ' low level cryptographic library')
            module.write_to_file(f)

    def gen_python_file(self):
        with open(self.python_module, 'w') as f:
            f.write('import _nettle\n')
            for obj in sorted(self.objects, key=lambda o: o.name):
                obj.write_python_subclass(f)

    def write_class_file(self, filename, classes, nettle_headers,
                         pynettle_headers=[]):
        with open(filename, 'w') as f:
            f.write('#include <Python.h>\n')
            f.write('#include <structmember.h>\n')
            f.write('#include "{}"\n'.format(self.header_file))
            for header in sorted(nettle_headers):
                f.write('#include <{}>\n'.format(header))
            for header in sorted(pynettle_headers):
                f.write('#include "{}"\n'.format(header))
            self.write_python2_buffer_struct(f)
            f.write('\n')
            for cls in classes:
                cls.write_to_file(f)

    def write_doc_file(self, filename, title, example, classes):
        with open(filename, 'w') as f:
            f.write('{}\n'.format(title))
            f.write('{}\n\n'.format('=' * len(title)))
            f.write('Example\n')
            f.write('-------\n')
            f.write('.. doctest::\n\n')
            f.write(example)
            f.write('\n\n')
            for cls in classes:
                cls.write_docs_to_file(f)


gen = Generator()
gen.gen_hash_file(hashes)
gen.gen_cipher_file(ciphers, ciphermodes)
gen.gen_mac_file(macs)
gen.gen_pubkey_file()
gen.gen_exceptions(exceptions)
gen.gen_header_file()
gen.gen_mod_file()
gen.gen_python_file()
