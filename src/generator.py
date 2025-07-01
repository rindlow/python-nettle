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
    {'name': 'sha3_128', 'headers': ['sha3.h'], 'digest': False, 'shake': True,
     'docstring': docstrings.sha3_224},
    {'name': 'sha3_224', 'headers': ['sha3.h'],
     'docstring': docstrings.sha3_224},
    {'name': 'sha3_256', 'headers': ['sha3.h'], 'shake': True,
     'docstring': docstrings.sha3_256},
    {'name': 'sha3_384', 'headers': ['sha3.h'],
     'docstring': docstrings.sha3_384},
    {'name': 'sha3_512', 'headers': ['sha3.h'],
     'docstring': docstrings.sha3_512},
    {'name': 'streebog512', 'headers': ['streebog.h'],
     'docstring': docstrings.streebog_512},
    {'name': 'streebog256', 'headers': ['streebog.h'],
     'docstring': docstrings.streebog_256},
    {'name': 'sm3', 'headers': ['sm3.h'],
     'docstring': docstrings.sm3}, ]

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
     'lenparam': True, 'variable_keylen': True, 'stream': True},
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
    {'name': 'salsa20', 'headers': ['salsa20.h'],
     'docstring': docstrings.salsa20,
     'lenparam': True, 'nonce': True},
    {'name': 'serpent', 'family': 'serpent', 'headers': ['serpent.h'],
     'docstring': docstrings.serpent,
     'lenparam': True, 'twofuncs': True, 'variable_keylen': True},
    {'name': 'sm4', 'family': 'sm4', 'headers': ['sm4.h'],
     'docstring': docstrings.sm4, 'twokeys': True, },
    {'name': 'twofish', 'family': 'twofish', 'headers': ['twofish.h'],
     'docstring': docstrings.twofish,
     'lenparam': True, 'twofuncs': True, 'variable_keylen': True},
]

ciphermodes = [
    {'name': 'CBC', 'docstring': 'Cipher Block Chaining',
     'headers': ['cbc.h'], 'iv': 'iv', 'twofuncs': True},
    {'name': 'CTR', 'docstring': 'Counter Mode',
     'headers': ['ctr.h'], 'iv': 'ctr'},
    {'name': 'GCM', 'docstring': 'Galois Counter Mode',
     'headers': ['gcm.h'], 'iv': 'iv', 'aead': True,
     'mode_key': True, 'digest_cipher_param': True, },
    {'name': 'EAX', 'docstring': 'The EAX mode is an AEAD mode which'
     ' combines CTR mode encryption, with a message authentication'
     ' based on CBC', 'headers': ['eax.h'],
     'iv': 'nonce', 'aead': True, 'mode_key': True,
     'update_cipher_param': True, 'digest_cipher_param': True,
     'set_cipher_param': True},
    {'name': 'CCM', 'docstring': 'Counter with Cipher Block Chaining'
     '-Message Authentication Code', 'headers': ['ccm.h'],
     'iv': 'nonce', 'aead': True, 'know_len': True,
     'update_cipher_param': True, 'digest_cipher_param': True,
     'set_cipher_param': True},
]

macs = [
    {'name': 'hmac_sha1', 'headers': ['hmac.h'],
     'docstring': docstrings.hmac,
     'digest': 'SHA1'},
    {'name': 'hmac_sha256', 'headers': ['hmac.h'],
     'docstring': docstrings.hmac,
     'digest': 'SHA256'},
    {'name': 'umac32', 'headers': ['umac.h'],
     'docstring': docstrings.umac,
     'nonce': 'variable'},
    {'name': 'umac64', 'headers': ['umac.h'],
     'docstring': docstrings.umac,
     'nonce': 'variable'},
    {'name': 'umac96', 'headers': ['umac.h'],
     'docstring': docstrings.umac,
     'nonce': 'variable'},
    {'name': 'umac128', 'headers': ['umac.h'],
     'docstring': docstrings.umac,
     'nonce': 'variable'},
    {'name': 'poly1305_aes', 'headers': ['poly1305.h'],
     'docstring': docstrings.poly1305,
     'nonce': 'fixed'},
]

exceptions = [
    {'name': 'BaseException', 'base': 'NULL',
     'docs': 'Generic Nettle Exception'},
    {'name': 'KeyLenError', 'base': 'BaseException',
     'docs': 'Key Length is not as expected'},
    {'name': 'DataLenError', 'base': 'BaseException',
     'docs': 'Data length is not a multiple of the block size'},
    {'name': 'LenMismatch', 'base': 'BaseException',
     'docs': 'Data length is not as specified earlier'},
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
    python_interface = '../nettle/autogen.pyi'
    cipher_doc_file = '../doc/source/ciphers.rst'
    ciphermode_doc_file = '../doc/source/ciphermodes.rst'
    hash_doc_file = '../doc/source/hashes.rst'
    mac_doc_file = '../doc/source/macs.rst'
    pubkey_doc_file = '../doc/source/pubkey.rst'

    def __init__(self):
        self.objects = []
        self.ciphers = []
        self.hashes = []

    @staticmethod
    def write_c_autogen_warning(f):
        f.write('/*\n'
                '  This file is auto generated (by src/generator.py).\n'
                '  All changes will be lost!\n'
                '*/\n')

    @staticmethod
    def write_python_autogen_warning(f):
        f.write('# This file is auto generated (by src/generator.py).\n'
                '# All changes will be lost!\n')

    def gen_hash_file(self, hashdata):
        headers = set([f for h in hashdata for f in h['headers']])
        classes = [Hash(p['name'], p.get('digest', True),
                        p.get('shake', False), p['docstring'])
                   for p in hashdata]
        self.objects.extend(classes)
        self.hashes = classes

        self.write_class_file(self.hash_file, classes, headers)
        self.write_doc_file(self.hash_doc_file, "Hashes",
                            docstrings.hash_example, classes)

    def gen_cipher_file(self, cipherdata, modedata):
        headers = set([h for m in cipherdata + modedata for h in m['headers']])
        cipher_list = [Cipher(defaultdict(none_factory(), c))
                       for c in cipherdata]
        modes = [CipherMode(defaultdict(none_factory(), m),
                            [c for c in cipherdata
                             if c.get('family') in ('aes', 'camellia')])
                 for m in modedata]
        classes = cipher_list + modes
        self.objects.extend(classes)
        self.ciphers = cipher_list

        self.write_class_file(self.cipher_file, classes, headers)
        self.write_doc_file(self.cipher_doc_file, "Ciphers",
                            docstrings.cipher_example, cipher_list)
        self.write_doc_file(self.ciphermode_doc_file, "Cipher Modes",
                            docstrings.ciphermode_example, modes)

    def gen_mac_file(self, macdata):
        headers = set(h for m in macdata for h in m['headers'])
        classes = [MAC(m) for m in macdata]
        self.objects.extend(classes)

        self.write_class_file(self.mac_file, classes, headers)
        self.write_doc_file(self.mac_doc_file, 'Keyed Hash Functions',
                            docstrings.mac_example, classes)

    def gen_pubkey_file(self):
        classes = [Yarrow(), RSAKeyPair(), RSAPubKey()]
        headers = ['yarrow.h', 'rsa.h']
        self.objects.extend(classes)

        self.write_class_file(self.pubkey_file, classes, headers,
                              system_headers=['fcntl.h'],
                              pynettle_headers=['nettle_asn1.h'])

        self.write_doc_file(self.pubkey_doc_file, 'Public Key Encryption',
                            docstrings.pubkey_example, classes)

    def gen_exceptions(self, exception_list):
        for e in exception_list:
            self.objects.append(CException(e['name'], 'nettle',
                                           e['docs'], e['base']))

    def gen_header_file(self):
        with open(self.header_file, 'w', encoding='utf8') as f:
            self.write_c_autogen_warning(f)
            f.write('#ifndef _NETTLE_H_\n#define _NETTLE_H_\n\n')
            f.write('#include <nettle/camellia.h>\n')
            f.write('#include <nettle/sha2.h>\n')
            f.write('#include <nettle/streebog.h>\n')
            for obj in self.objects:
                obj.write_decl_to_file(f, extern=True)
            f.write('#endif /* _NETTLE_H_ */\n')

    def gen_mod_file(self):
        with open(self.mod_file, 'w', encoding='utf8') as f:
            self.write_c_autogen_warning(f)
            f.write('#include <Python.h>\n')
            f.write('#include "{}"\n'.format(self.header_file))
            for obj in sorted(self.objects, key=lambda o: o.name):
                obj.write_decl_to_file(f, extern=False)

            module = CModule(name='_nettle', objects=self.objects,
                             doc='An interface to the Nettle'
                                 ' low level cryptographic library')
            module.write_to_file(f)

    def gen_python_file(self):
        with open(self.python_module, 'w', encoding='utf8') as f:
            self.write_python_autogen_warning(f)
            f.write('import _nettle\n')
            for obj in sorted(self.objects, key=lambda o: o.name):
                obj.write_python_subclass(f)
            if self.ciphers:
                f.write('ciphers = [{}]\n'.format(','.join(c.name
                                                           for c in
                                                           self.ciphers)))
            if self.hashes:
                f.write('class Hash: pass\n')
                f.write('class DigestableHash(Hash): pass\n')
                f.write('class ShakeableHash(Hash): pass\n')
                f.write('hashes = [{}]\n'.format(','.join(h.name
                                                          for h in
                                                          self.hashes)))
            if self.ciphers:
                f.write('class Cipher: ...\n')
                f.write('class SingleFuncCipher(Cipher): ...\n')
                f.write('class SingleKeyCipher(Cipher): ...\n')
                f.write('class DoubleKeyCipher(Cipher): ...\n')
                f.write('class NonceCipher(Cipher): ...\n')
                f.write('class StreamCipher(Cipher): ...\n')
                f.write('class InvertableKeyCipher(Cipher): ...\n')
                f.write('class ParitySensitiveCipher(Cipher): ...\n')
                written_families = set()
                for c in self.ciphers:
                    if c.family is not None and c.family not in written_families:
                        f.write(f'class {c.family.capitalize()}FamilyCipher(Cipher): ... \n')
                        written_families.add(c.family)

            f.write('class CipherMode: pass\n')
            f.write('class AEADCipherMode(CipherMode): pass\n')
            f.write('class MAC: pass\n')
            f.write('class NonceMAC(MAC): pass\n')

    def gen_interface_file(self, hash_list, cipher_list, ciphermode_list, 
                           exception_list, mac_list):
        with open(self.python_interface, 'w', encoding='utf8') as f:
            self.write_python_autogen_warning(f)
            f.write('import typing as t\n')
            f.write('class Hash(t.Protocol):\n')
            f.write('    def __init__(self, msg: bytes = ...) -> None: ...\n')
            f.write('    def copy(self) -> t.Self: ...\n')
            f.write('    def update(self, msg: bytes) -> None: ...\n')
            f.write('class DigestableHash(Hash, t.Protocol):\n')
            f.write('    def digest(self) -> bytes: ...\n')
            f.write('    def hexdigest(self) -> str: ...\n')
            f.write('class ShakeableHash(Hash, t.Protocol):\n')
            f.write('    def shake(self, length: int) -> bytes: ...\n')
            f.write('    def shake_output(self, length: int) -> bytes: ...\n')
            for h in hash_list:
                protocols = []
                if h.get('digest', True):
                    protocols.append('DigestableHash')
                if h.get('shake'):
                    protocols.append('ShakeableHash')
                f.write('class {}({}): ...\n'.format(h['name'], ', '.join(protocols)))
            f.write('class Cipher(t.Protocol):\n')
            f.write('    key_size: int\n')
            f.write('    def set_encrypt_key(self, key: bytes) -> None: ...\n')
            f.write('    def set_decrypt_key(self, key: bytes) -> None: ...\n')
            f.write('    def encrypt(self, msg: bytes) -> bytes: ...\n')
            f.write('    def decrypt(self, msg: bytes) -> bytes: ...\n')
            f.write('class SingleFuncCipher(Cipher, t.Protocol):\n')
            f.write('    def crypt(self, msg: bytes) -> bytes: ...\n')
            f.write('class SingleKeyCipher(Cipher, t.Protocol):\n')
            f.write('    def set_key(self, key: bytes) -> None: ...\n')
            f.write('class DoubleKeyCipher(Cipher, t.Protocol): ...\n')
            f.write('class NonceCipher(Cipher, t.Protocol):\n')
            f.write('    def set_nonce(self, nonce: bytes) -> None: ...\n')
            f.write('class StreamCipher(Cipher, t.Protocol):\n')
            f.write('    block_size: int\n')
            f.write('class InvertableKeyCipher(Cipher, t.Protocol):\n')
            f.write('    def invert_key(self) -> None: ...\n')
            f.write('class ParitySensitiveCipher(Cipher, t.Protocol):\n')
            f.write('    def check_parity(self, key: bytes) -> bool: ...\n')
            f.write('    def fix_parity(self, key: bytes) -> bytes: ...\n')
            written_families = set()
            for c in cipher_list:
                if 'family' not in c or c['family'] not in written_families:
                    protocols = []
                    init_args = []
                    if not c.get('twofuncs'):
                        protocols.append('SingleFuncCipher')
                        # f.write('    def crypt(self, msg: bytes) -> bytes: ...\n')
                    if c.get('twokeys'):
                        protocols.append('DoubleKeyCipher')
                        init_args.extend(['encrypt_key: bytes | None = None',
                                          'decrypt_key: bytes | None = None'])
                    else:
                        protocols.append('SingleKeyCipher')
                        # f.write('    def set_key(self, key: bytes) -> None: ...\n')
                        init_args.append('key: bytes | None = None')
                    if c.get('nonce'):
                        protocols.append('NonceCipher')
                        # f.write('    def set_nonce(self, nonce: bytes) -> None: ...\n')
                        init_args.append('nonce: bytes | None = None')
                    if c.get('invert'):
                        protocols.append('InvertableKeyCipher')
                        # f.write('    def invert_key(self) -> None: ...\n')
                    if c.get('parity'):
                        protocols.append('ParitySensitiveCipher')
                        # f.write('    def check_parity(self, key: bytes) -> bool: ...\n')
                        # f.write('    def fix_parity(self, key: bytes) -> bytes: ...\n')

                if 'family' in c:
                    if c['family'] not in written_families:
                        written_families.add(c['family'])
                        f.write(f'class {c["family"].capitalize()}FamilyCipher({", ".join(protocols)}, t.Protocol):\n')
                        f.write(f'    def __init__(self, {", ".join(init_args)}) -> None: ...\n')
                    f.write(f'class {c["name"]}({c["family"].capitalize()}FamilyCipher):\n')
                    f.write('    key_size: int\n')
                else:
                    if len(protocols) == 0:
                        protocols = ['Cipher']
                    f.write(f'class {c["name"]}({", ".join(protocols)}):\n')
                    f.write('    key_size: int\n')
                    f.write(f'    def __init__(self, {", ".join(init_args)}) -> None: ...\n')

            f.write('class CipherMode(t.Protocol):\n')
            f.write('    def encrypt(self, msg: bytes) -> bytes: ...\n')
            f.write('    def decrypt(self, msg: bytes) -> bytes: ...\n')
            f.write('class AEADCipherMode(CipherMode, t.Protocol):\n')
            f.write('    def update(self, msg: bytes) -> None: ...\n')
            f.write('    def digest(self) -> bytes: ...\n')            
            f.write('    def hexdigest(self) -> str: ...\n')            
            for m in ciphermode_list:
                if 'aead' in m:
                    protocol = 'AEADCipherMode'
                else:
                    protocol = 'CipherMode'
                init_args = f'cipher: Cipher, {m["iv"]}: bytes'
                if 'know_len' in m:
                    init_args += ', authlen: int, msglen: int, taglen: int'
                f.write(f'class {m["name"]}({protocol}):\n')
                f.write(f'    def __init__(self, {init_args}) -> None: ...\n')

            for e in exception_list:
                f.write(f'class {e["name"]}(Exception): ...\n')

            f.write('class MAC(t.Protocol):\n')
            f.write('    def __init__(self, key: bytes | None = None) -> None: ...\n')
            f.write('    def set_key(self, key: bytes) -> None: ...\n')
            f.write('    def update(self, msg: bytes) -> None: ...\n')
            f.write('    def digest(self) -> bytes: ...\n')
            f.write('    def hexdigest(self) -> str: ...\n')
            f.write('class NonceMAC(MAC, t.Protocol):\n')
            f.write('    def __init__(self, key: bytes | None = None, nonce: bytes | None = None) -> None: ...\n')
            f.write('    def set_nonce(self, nonce: bytes) -> None: ...\n')
            for m in mac_list:
                if 'nonce' in m:
                    f.write(f'class {m["name"]}(NonceMAC):\n')
                else:
                    f.write(f'class {m["name"]}(MAC):\n')
                f.write('    digest_size: int\n')

            f.write('class RSAKeyPair:\n')
            f.write('    public_key: RSAPubKey\n')
            f.write('    yarrow: Yarrow\n')
            f.write('    def __init__(self, yarrow: Yarrow | None = None) -> None: ...\n')
            f.write('    def decrypt(self, msg: bytes) -> bytes: ...\n')
            f.write('    def encrypt(self, msg: bytes) -> bytes: ...\n')
            f.write('    def from_pkcs1(self, buffer: bytes) -> None: ...\n')
            f.write('    def from_pkcs8(self, buffer: bytes) -> None: ...\n')
            f.write('    def genkey(self, n_size: int, e_size: int) -> None: ...\n')
            f.write('    def read_key(self, filename: str) -> None: ...\n')
            f.write('    def read_pkcs1_key(self, key: bytes) -> None: ...\n')
            f.write('    def read_pkcs8_key(self, key: bytes) -> None: ...\n')
            f.write('    def sign(self, hash: Hash) -> bytes: ...\n')
            f.write('    def to_pkcs1_key(self) -> bytes: ...\n')
            f.write('    def verify(self, signature: bytes, hash: Hash) -> bool: ...\n')
            f.write('    def write_key(self, filename: str) -> None: ...\n')
            f.write('class RSAPubKey:\n')
            f.write('    yarrow: Yarrow\n')
            f.write('    def __init__(self, yarrow: Yarrow | None = None) -> None: ...\n')
            f.write('    def encrypt(self, msg: bytes) -> bytes: ...\n')
            f.write('    def from_pkcs1(self, key: bytes) -> None: ...\n')
            f.write('    def from_pkcs8(self, key: bytes) -> None: ...\n')
            f.write('    def to_pkcs8_key(self) -> bytes: ...\n')
            f.write('    def read_key(self, filename: str) -> None: ...\n')
            f.write('    def read_key_from_cert(self, cert: bytes) -> None: ...\n')
            f.write('    def verify(self, signature: bytes, hash: Hash) -> bool: ...\n')
            f.write('    def write_key(self, filename: str) -> None: ...\n')
            f.write('class Yarrow:\n')
            f.write('    def random(self, length: int) -> bytes: ...\n')

    def write_class_file(self, filename, classes, nettle_headers,
                         system_headers=None, pynettle_headers=None):
        with open(filename, 'w', encoding='utf8') as f:
            self.write_c_autogen_warning(f)
            f.write('#include <Python.h>\n')
            f.write('#include <structmember.h>\n')
            f.write('#include "{}"\n'.format(self.header_file))
            if system_headers is not None:
                for header in sorted(system_headers):
                    f.write('#include <{}>\n'.format(header))
            for header in sorted(nettle_headers):
                f.write('#include <nettle/{}>\n'.format(header))
            if pynettle_headers is not None:
                for header in sorted(pynettle_headers):
                    f.write('#include "{}"\n'.format(header))
            f.write('\n')
            for cls in classes:
                cls.write_to_file(f)

    def write_doc_file(self, filename, title, example, classes):
        with open(filename, 'w', encoding='utf8') as f:
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
gen.gen_interface_file(hashes, ciphers, ciphermodes, exceptions, macs)
