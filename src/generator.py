#!/usr/bin/env python3

from CModule import CModule
from Hash import Hash
from Cipher import Cipher

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

aesdocs = 'AES is a block cipher, specified by NIST as a replacement' \
     ' for the older DES standard. The standard is the result of a' \
     ' competition between cipher designers. The winning design, also known' \
     ' as RIJNDAEL, was constructed by Joan Daemen and Vincent Rijnmen.' \
     ' Like all the AES candidates, the winning design uses a block size of' \
     ' 128 bits, or 16 octets, and three possible key-size, 128, 192 and 256' \
     ' bits (16, 24 and 32 octets) being the allowed key sizes. It does not' \
     ' have any weak keys.'

camelliadocs = 'Camellia is a block cipher developed by Mitsubishi and' \
     ' Nippon Telegraph and Telephone Corporation, described in RFC3713. It' \
     ' is recommended by some Japanese and European authorities as an' \
     ' alternative to AES, and it is one of the selected algorithms in' \
     ' the New European Schemes for Signatures, Integrity and' \
     ' Encryption (NESSIE) project. The algorithm is patented. The' \
     ' implementation in Nettle is derived from the implementation' \
     ' released by NTT under the GNU LGPL (v2.1 or later), and relies' \
     ' on the implicit patent license of the LGPL. There is also a' \
     ' statement of royalty-free licensing for Camellia at' \
     ' http://www.ntt.co.jp/news/news01e/0104/010417.html, but this' \
     ' statement has some limitations which seem problematic for free' \
     ' software.' \
     ' Camellia uses a the same block size and key sizes as AES: The block' \
     ' size is 128 bits (16 octets), and the supported key sizes are' \
     ' 128, 192, and 256 bits. The variants with 192 and 256 bit keys' \
     ' are identical, except for the key setup.'

arcfourdocs = 'ARCFOUR is a stream cipher, also known under the trade marked' \
     'name RC4, and it is one of the fastest ciphers around. A' \
     ' problem is that the key setup of ARCFOUR is quite weak, you should' \
     ' never use keys with structure, keys that are ordinary' \
     ' passwords, or sequences of keys like "secret:1", "secret:2"' \
     ' .... If you have keys that don’t look like random bit strings,' \
     ' and you want to use ARCFOUR, always hash the key before feeding' \
     ' it to ARCFOUR. Furthermore, the initial bytes of the generated' \
     ' key stream leak information about the key; for this reason, it' \
     ' is recommended to discard the first 512 bytes of the key' \
     ' stream.'

ciphers = [
    {'name': 'arcfour', 'family': None, 'headers': ['arcfour.h'],
     'docstring': aesdocs, 'lenparam': True, 'twokeys': False,
     'twofuncs': False, 'invert': False},
    {'name': 'aes128', 'family': 'aes', 'headers': ['aes.h', 'cbc.h',
                                                    'ctr.h', 'gcm.h'],
     'modes': ['ecb', 'cbc', 'ctr', 'gcm'], 'lenparam': False,
     'twokeys': True, 'twofuncs': True, 'invert': True, 'docstring': aesdocs},
    {'name': 'aes192', 'family': 'aes', 'headers': ['aes.h', 'cbc.h',
                                                    'ctr.h', 'gcm.h'],
     'modes': ['ecb', 'cbc', 'ctr', 'gcm'], 'lenparam': False,
     'twokeys': True, 'twofuncs': True, 'invert': True, 'docstring': aesdocs},
    {'name': 'aes256', 'family': 'aes', 'headers': ['aes.h', 'cbc.h',
                                                    'ctr.h', 'gcm.h'],
     'modes': ['ecb', 'cbc', 'ctr', 'gcm'], 'lenparam': False,
     'twokeys': True, 'twofuncs': True, 'invert': True, 'docstring': aesdocs},
    {'name': 'camellia128', 'family': 'camellia',
     'headers': ['camellia.h', 'cbc.h', 'ctr.h'],
     'modes': ['ecb', 'cbc', 'ctr'], 'lenparam': False, 'twokeys': True,
     'twofuncs': False, 'invert': True, 'docstring': camelliadocs},
    {'name': 'camellia192', 'family': 'camellia',
     'headers': ['camellia.h', 'cbc.h', 'ctr.h'],
     'modes': ['ecb', 'cbc', 'ctr'], 'lenparam': False, 'twokeys': True,
     'twofuncs': False, 'invert': True, 'docstring': camelliadocs},
    {'name': 'camellia256', 'family': 'camellia',
     'headers': ['camellia.h', 'cbc.h', 'ctr.h'],
     'modes': ['ecb', 'cbc', 'ctr'], 'lenparam': False, 'twokeys': True,
     'twofuncs': False, 'invert': True, 'docstring': camelliadocs},
]


class Generator:
    hash_file = 'nettle_hashes.c'
    cipher_file = 'nettle_ciphers.c'
    mod_file = 'nettle.c'

    def __init__(self):
        self.objects = []

    def write_python2_buffer_struct(self, f):
        f.write('#if PY_MAJOR_VERSION < 3\n'
                'typedef struct py2buf_struct {\n'
                '  const uint8_t *buf;\n'
                '  int len;\n'
                '} nettle_py2buf;\n'
                '#endif\n')

    def gen_hash_file(self, hashdata):
        with open(self.hash_file, 'w') as f:
            f.write('#include <Python.h>\n')
            f.write('#include <structmember.h>\n')
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
                self.objects.append(h['name'])

    def gen_cipher_file(self, cipherdata):
        with open(self.cipher_file, 'w') as f:
            f.write('#include <Python.h>\n')
            f.write('#include <structmember.h>\n')
            headers = set()
            for c in cipherdata:
                headers.update(set(c['headers']))
            for header in sorted(headers):
                f.write('#include <nettle/{}>\n'.format(header))
            self.write_python2_buffer_struct(f)
            f.write('\n')

            for c in ciphers:
                if 'modes' in c:
                    for mode in c['modes']:
                        objname = '{}_{}'.format(c['name'], mode)
                        cipherclass = Cipher(c['name'],
                                             family=c['family'],
                                             docs=c['docstring'],
                                             lenparam=c['lenparam'],
                                             twokeys=c['twokeys'],
                                             twofuncs=c['twofuncs'],
                                             invert=c['invert'],
                                             mode=mode)
                        cipherclass.write_to_file(f)
                        self.objects.append(objname)
                else:
                    cipherclass = Cipher(c['name'],
                                         family=c['family'],
                                         docs=c['docstring'],
                                         lenparam=c['lenparam'],
                                         twokeys=c['twokeys'],
                                         twofuncs=c['twofuncs'],
                                         invert=c['invert'])
                    cipherclass.write_to_file(f)
                    self.objects.append(c['name'])

    def gen_mod_file(self):
        with open(self.mod_file, 'w') as f:
            f.write('#include <Python.h>\n')
            for object in sorted(self.objects):
                f.write('extern PyTypeObject pynettle_{}_Type;\n'
                        .format(object))

            module = CModule(name='nettle', objects=self.objects,
                             doc='An interface to the Nettle'
                             ' low level cryptographic library')
            module.write_to_file(f)

gen = Generator()
gen.gen_hash_file(hashes)
gen.gen_cipher_file(ciphers)
gen.gen_mod_file()
