#!/usr/bin/env python3
#
# generator.py
#
# Copyright (C) 2017-2026 Henrik Rindlöw
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

import pathlib
from collections.abc import Sequence
from typing import TYPE_CHECKING, TextIO

import docstrings
import params
from c_class import CClass
from c_exception import CException
from c_module import CModule
from cipher import Cipher
from cipher_mode import CipherMode
from hash import Hash
from mac import MAC
from pubkey import RSAKeyPair, RSAPubKey
from randomness import Random

if TYPE_CHECKING:
    from protocols import Object


class Generator:

    def __init__(self) -> None:
        self.objects: list[Object] = []
        self.ciphers: list[Cipher] = []
        self.hashes: list[Hash] = []
        filepath = pathlib.Path(__file__)
        rootpath = filepath.parent.parent
        srcpath = rootpath / 'src'
        nettlepath = rootpath / 'nettle'
        docpath = rootpath / 'doc' / 'source'
        self.cipher_file = srcpath / 'nettle_ciphers.c'
        self.hash_file = srcpath / 'nettle_hashes.c'
        self.mac_file = srcpath / 'nettle_macs.c'
        self.random_file = srcpath / 'nettle_random.c'
        self.mod_file = srcpath / 'nettle.c'
        self.header_file = srcpath / 'nettle.h'
        self.header_include_path = self.header_file.name
        self.pubkey_file = srcpath / 'nettle_pubkey.c'
        self.python_module = nettlepath / 'autogen.py'
        self.python_interface = nettlepath / 'autogen.pyi'
        self.cipher_doc_file = docpath / 'ciphers.rst'
        self.ciphermode_doc_file = docpath / 'ciphermodes.rst'
        self.hash_doc_file = docpath / 'hashes.rst'
        self.mac_doc_file = docpath / 'macs.rst'
        self.random_doc_file = docpath / 'random.rst'
        self.pubkey_doc_file = docpath / 'pubkey.rst'

    @staticmethod
    def write_c_autogen_warning(f: TextIO) -> None:
        f.write('/*\n'
                '  This file is auto generated (by generator/generator.py).\n'
                '  All changes will be lost!\n'
                '*/\n')

    @staticmethod
    def write_python_autogen_warning(f: TextIO) -> None:
        f.write('# This file is auto generated (by generator/generator.py).\n'
                '# All changes will be lost!\n')

    def generate(self) -> None:
        self.gen_hash_file()
        self.gen_cipher_file()
        self.gen_mac_file()
        self.gen_random_file()
        self.gen_pubkey_file()
        self.gen_exceptions()
        self.gen_header_file()
        self.gen_mod_file()
        self.gen_python_file()
        self.gen_interface_file()

    def gen_hash_file(self) -> None:
        headers = list({f for h in params.hashes for f in h['headers']})
        classes = [Hash(p) for p in params.hashes]
        self.objects.extend(classes)
        self.hashes = classes

        self.write_class_file(self.hash_file, classes, headers)
        self.write_doc_file(self.hash_doc_file, "Hashes",
                            docstrings.hash_example, classes)

    def gen_cipher_file(self) -> None:
        headers = list({h for m in params.ciphers + params.ciphermodes for h in m['headers']})
        cipher_list = [Cipher(c) for c in params.ciphers]
        modes = [CipherMode(m, [c for c in params.ciphers
                                if c.get('family') in ('aes', 'camellia')])
                 for m in params.ciphermodes]
        classes = cipher_list + modes
        self.objects.extend(classes)
        self.ciphers = cipher_list

        self.write_class_file(self.cipher_file, classes, headers)
        self.write_doc_file(self.cipher_doc_file, "Ciphers",
                            docstrings.cipher_example, cipher_list)
        self.write_doc_file(self.ciphermode_doc_file, "Cipher Modes",
                            docstrings.ciphermode_example, modes)

    def gen_mac_file(self) -> None:
        headers = list({h for m in params.macs for h in m['headers']})
        classes = [MAC(m) for m in params.macs]
        self.objects.extend(classes)

        self.write_class_file(self.mac_file, classes, headers)
        self.write_doc_file(self.mac_doc_file, 'Keyed Hash Functions',
                            docstrings.mac_example, classes)

    def gen_pubkey_file(self) -> None:
        classes: list[CClass] = [RSAKeyPair(), RSAPubKey()]
        headers = ['yarrow.h', 'rsa.h']
        self.objects.extend(classes)

        self.write_class_file(self.pubkey_file, classes, headers,
                              system_headers=['fcntl.h', 'stdio.h'],
                              pynettle_headers=['nettle_asn1.h'])

        self.write_doc_file(self.pubkey_doc_file, 'Public Key Encryption',
                            docstrings.pubkey_example, classes)

    def gen_random_file(self) -> None:
        headers = list({f for h in params.random for f in h['headers']})
        classes = [Random(p) for p in params.random]
        self.objects.extend(classes)

        self.write_class_file(self.random_file, classes, headers,
                              system_headers=['fcntl.h', 'stdio.h'])
        self.write_doc_file(self.random_doc_file, "Randomness",
                            docstrings.random_example, classes)

    def gen_exceptions(self) -> None:
        for e in params.exceptions:
            self.objects.append(CException(e['name'], 'nettle',
                                           e['docstring'], e['base']))

    def gen_header_file(self) -> None:
        with self.header_file.open('w', encoding='utf8') as f:
            self.write_c_autogen_warning(f)
            f.write('#ifndef _NETTLE_H_\n#define _NETTLE_H_\n\n')
            f.write('#include <nettle/camellia.h>\n')
            f.write('#include <nettle/sha2.h>\n')
            f.write('#include <nettle/streebog.h>\n')
            for obj in self.objects:
                obj.write_decl_to_file(f, extern=True)
            f.write('#endif /* _NETTLE_H_ */\n')

    def gen_mod_file(self) -> None:
        with self.mod_file.open('w', encoding='utf8') as f:
            self.write_c_autogen_warning(f)
            f.write('#include <Python.h>\n')
            f.write(f'#include "{self.header_include_path}"\n')
            for obj in sorted(self.objects, key=lambda o: o.name):
                obj.write_decl_to_file(f, extern=False)

            module = CModule(name='_nettle', objects=self.objects,
                             doc='An interface to the Nettle'
                                 ' low level cryptographic library')
            module.write_to_file(f)

    def gen_python_file(self) -> None:
        with self.python_module.open('w', encoding='utf8') as f:
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
                f.write('class KeyWrapCipher(Cipher): ...\n')
                written_families: set[str] = set()
                for c in self.ciphers:
                    if c.family is not None and c.family not in written_families:
                        f.write(f'class {c.family.capitalize()}'
                                'FamilyCipher(Cipher): ... \n')
                        written_families.add(c.family)

            f.write('class CipherMode: pass\n')
            f.write('class AEADCipherMode(CipherMode): pass\n')
            f.write('class MAC: pass\n')
            f.write('class NonceMAC(MAC): pass\n')

    def gen_interface_file(self) -> None:
        with self.python_interface.open('w', encoding='utf8') as f:
            self.write_python_autogen_warning(f)
            f.write('import typing as t\n')
            f.write('class Hash(t.Protocol):\n')
            f.write('    def __init__(self, msg: bytes = ...) -> None: ...\n')
            f.write('    def copy(self) -> t.Self: ...\n')
            f.write('    def update(self, msg: bytes) -> None: ...\n')
            f.write('class DigestableHash(Hash, t.Protocol):\n')
            f.write('    digest_size: int\n')
            f.write('    def digest(self) -> bytes: ...\n')
            f.write('    def hexdigest(self) -> str: ...\n')
            f.write('class ShakeableHash(Hash, t.Protocol):\n')
            f.write('    def shake(self, length: int) -> bytes: ...\n')
            f.write('    def shake_output(self, length: int) -> bytes: ...\n')
            for h in params.hashes:
                protocols = []
                if h.get('digest', True):
                    protocols.append('DigestableHash')
                    ellipsis = ''
                else:
                    ellipsis = ' ...'
                if h.get('shake'):
                    protocols.append('ShakeableHash')
                f.write(f"class {h['name']}({', '.join(protocols)}):{ellipsis}\n")
                if h.get('digest', True):
                    f.write('    digest_size: int\n')
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
            f.write('class KeyWrapCipher(Cipher, t.Protocol):\n')
            f.write('    def keywrap(self, cleartext: bytes) -> bytes: ...\n')
            f.write('    def keyunwrap(self, ciphertext: bytes) -> bytes: ...\n')
            written_families: set[str] = set()
            protocols: list[str] = []
            init_args: list[str] = []
            for c in params.ciphers:
                if 'family' not in c or c['family'] not in written_families:
                    protocols = []
                    init_args = []
                    if not c.get('twofuncs'):
                        protocols.append('SingleFuncCipher')
                    if c.get('twokeys'):
                        protocols.append('DoubleKeyCipher')
                        init_args.extend(['encrypt_key: bytes | None = None',
                                          'decrypt_key: bytes | None = None'])
                    else:
                        protocols.append('SingleKeyCipher')
                        init_args.append('key: bytes | None = None')
                    if c.get('nonce'):
                        protocols.append('NonceCipher')
                        init_args.append('nonce: bytes | None = None')
                    if c.get('invert'):
                        protocols.append('InvertableKeyCipher')
                    if c.get('parity'):
                        protocols.append('ParitySensitiveCipher')
                    if c.get('keywrap'):
                        protocols.append('KeyWrapCipher')

                if 'family' in c:
                    if c['family'] not in written_families:
                        written_families.add(c['family'])
                        f.write(f'class {c["family"].capitalize()}'
                                f'FamilyCipher({", ".join(protocols)}, t.Protocol):\n')
                        f.write(f'    def __init__(self, {", ".join(init_args)})'
                                ' -> None: ...\n')
                        if 'stream' not in c:
                            f.write('    block_size: int\n')
                    f.write(f'class {c["name"]}({c["family"].capitalize()}'
                            'FamilyCipher):\n')
                    f.write('    key_size: int\n')
                    if 'stream' not in c:
                        f.write('    block_size: int\n')

                else:
                    if len(protocols) == 0:
                        protocols = ['Cipher']
                    f.write(f'class {c["name"]}({", ".join(protocols)}):\n')
                    f.write('    key_size: int\n')
                    f.write(f'    def __init__(self, {", ".join(init_args)})'
                            ' -> None: ...\n')

            f.write('class CipherMode(t.Protocol):\n')
            f.write('    def encrypt(self, msg: bytes) -> bytes: ...\n')
            f.write('    def decrypt(self, msg: bytes) -> bytes: ...\n')
            f.write('class AEADCipherMode(CipherMode, t.Protocol):\n')
            f.write('    def update(self, msg: bytes) -> None: ...\n')
            f.write('    def digest(self) -> bytes: ...\n')
            f.write('    def hexdigest(self) -> str: ...\n')
            for m in params.ciphermodes:
                if 'aead' in m:
                    protocol = 'AEADCipherMode'
                else:
                    protocol = 'CipherMode'
                init_args = ['cipher: Cipher', f'{m["iv"]}: bytes']
                if 'know_len' in m:
                    init_args.extend(['authlen: int', 'msglen: int', 'taglen: int'])
                f.write(f'class {m["name"]}({protocol}):\n')
                f.write(f"    def __init__(self, {', '.join(init_args)})"
                        ' -> None: ...\n')

            for e in params.exceptions:
                f.write(f'class {e["name"]}(Exception): ...\n')

            f.write('class MAC(t.Protocol):\n')
            f.write('    digest_size: int\n')
            f.write('    def __init__(self, key: bytes | None = None) -> None: ...\n')
            f.write('    def set_key(self, key: bytes) -> None: ...\n')
            f.write('    def update(self, msg: bytes) -> None: ...\n')
            f.write('    def digest(self) -> bytes: ...\n')
            f.write('    def hexdigest(self) -> str: ...\n')
            f.write('class NonceMAC(MAC, t.Protocol):\n')
            f.write('    def __init__(self, key: bytes | None = None, nonce: bytes | None = None) -> None: ...\n')
            f.write('    def set_nonce(self, nonce: bytes) -> None: ...\n')
            for m in params.macs:
                if 'nonce' in m:
                    f.write(f'class {m["name"]}(NonceMAC):\n')
                else:
                    f.write(f'class {m["name"]}(MAC):\n')
                f.write('    digest_size: int\n')

            for r in params.random:
                f.write(f'class {r["name"]}:\n')
                f.write('    def random(self, length: int) -> bytes: ...\n')

            f.write('class RSAKeyPair:\n')
            f.write('    public_key: RSAPubKey\n')
            f.write('    yarrow: Yarrow256\n')
            f.write('    size: int\n')
            f.write('    def __init__(self, yarrow: Yarrow256 | None = None) -> None: ...\n')
            f.write('    def decrypt(self, msg: bytes) -> bytes: ...\n')
            f.write('    def encrypt(self, msg: bytes) -> bytes: ...\n')
            for hashfunc in ('sha256', 'sha384', 'sha512'):
                f.write(f'    def oaep_{hashfunc}_decrypt(self, msg: bytes, label: bytes | None = None) -> bytes: ...\n')
                f.write(f'    def oaep_{hashfunc}_encrypt(self, msg: bytes, label: bytes | None = None) -> bytes: ...\n')
            f.write('    def from_pkcs1(self, buffer: bytes) -> None: ...\n')
            f.write('    def from_pkcs8(self, buffer: bytes) -> None: ...\n')
            f.write('    def from_params(self, n: bytes, e: bytes, d: bytes, p: bytes, q: bytes, a: bytes, b: bytes, c: bytes) -> None: ...\n')
            f.write('    def genkey(self, n_size: int, e_size: int) -> None: ...\n')
            f.write('    def read_key(self, filename: str) -> None: ...\n')
            f.write('    def read_pkcs1_key(self, key: bytes) -> None: ...\n')
            f.write('    def read_pkcs8_key(self, key: bytes) -> None: ...\n')
            f.write('    def sign(self, hash: Hash) -> bytes: ...\n')
            f.write('    def to_pkcs1_key(self) -> bytes: ...\n')
            f.write('    def verify(self, signature: bytes, hash: Hash) -> bool: ...\n')
            f.write('    def write_key(self, filename: str) -> None: ...\n')
            f.write('class RSAPubKey:\n')
            f.write('    yarrow: Yarrow256\n')
            f.write('    size: int\n')
            f.write('    def __init__(self, yarrow: Yarrow256 | None = None) -> None: ...\n')
            f.write('    def encrypt(self, msg: bytes) -> bytes: ...\n')
            for hashfunc in ('sha256', 'sha384', 'sha512'):
                f.write(f'    def oaep_{hashfunc}_encrypt(self, msg: bytes, label: bytes | None = None) -> bytes: ...\n')
            f.write('    def from_cert(self, cert: bytes) -> None: ...\n')
            f.write('    def from_pkcs1(self, key: bytes) -> None: ...\n')
            f.write('    def from_pkcs8(self, key: bytes) -> None: ...\n')
            f.write('    def from_params(self, n: bytes, e: bytes) -> None: ...\n')
            f.write('    def to_pkcs8_key(self) -> bytes: ...\n')
            f.write('    def read_key(self, filename: str) -> None: ...\n')
            f.write('    def verify(self, signature: bytes, hash: Hash) -> bool: ...\n')
            f.write('    def write_key(self, filename: str) -> None: ...\n')


    def write_class_file(self, filepath: pathlib.Path, classes: Sequence[CClass],
                         nettle_headers: list[str],
                         system_headers: list[str] | None = None,
                         pynettle_headers: list[str] | None = None) -> None:
        with filepath.open('w', encoding='utf8') as f:
            self.write_c_autogen_warning(f)
            f.write('#include <Python.h>\n')
            f.write('#include <structmember.h>\n')
            f.write(f'#include "{self.header_include_path}"\n')
            if system_headers is not None:
                for header in sorted(system_headers):
                    f.write(f'#include <{header}>\n')
            for header in sorted(nettle_headers):
                f.write(f'#include <nettle/{header}>\n')
            if pynettle_headers is not None:
                for header in sorted(pynettle_headers):
                    f.write(f'#include "{header}"\n')
            f.write('\n')
            for cls in classes:
                cls.write_to_file(f)

    def write_doc_file(self, filepath: pathlib.Path, title: str, example: str,
                       classes: Sequence[CClass]) -> None:
        with filepath.open('w', encoding='utf8') as f:
            f.write(f'{title}\n')
            f.write('{}\n\n'.format('=' * len(title)))
            f.write('Example\n')
            f.write('-------\n')
            f.write('.. doctest::\n\n')
            f.write(example)
            f.write('\n\n')
            for cls in classes:
                cls.write_docs_to_file(f)


if __name__ == '__main__':
    Generator().generate()
