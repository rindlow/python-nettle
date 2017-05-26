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
     
camelliadocs = 'Camellia is a block cipher developed by Mitsubishi and Nippon' \
     ' Telegraph and Telephone Corporation, described in RFC3713. It' \
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

ciphers = [
    {'name': 'aes128', 'family': 'aes', 'headers': ['aes.h', 'cbc.h', 'ctr.h'],
     'modes': ['ecb', 'cbc', 'ctr'],
     'docstring': aesdocs},
    {'name': 'aes192', 'family': 'aes', 'headers': ['aes.h', 'cbc.h', 'ctr.h'],
     'modes': ['ecb', 'cbc', 'ctr'],
     'docstring': aesdocs},
    {'name': 'aes256', 'family': 'aes', 'headers': ['aes.h', 'cbc.h', 'ctr.h'],
     'modes': ['ecb', 'cbc', 'ctr'],
     'docstring': aesdocs},
    {'name': 'camellia128', 'family': 'camellia',
     'headers': ['camellia.h', 'cbc.h', 'ctr.h'],
     'modes': ['ecb', 'cbc', 'ctr'],
     'docstring': camelliadocs},
    {'name': 'camellia192', 'family': 'camellia',
     'headers': ['camellia.h', 'cbc.h', 'ctr.h'],
     'modes': ['ecb', 'cbc', 'ctr'],
     'docstring': camelliadocs},
    {'name': 'camellia256', 'family': 'camellia',
     'headers': ['camellia.h', 'cbc.h', 'ctr.h'],
     'modes': ['ecb', 'cbc', 'ctr'],
     'docstring': camelliadocs},
    
]

class Generator:
    hash_file = 'nettle_hashes.c'
    cipher_file = 'nettle_ciphers.c'
    mod_file = 'nettle.c'
    
    def __init__(self):
        self.objects = []

    def gen_hash_file(self, hashdata):
        with open(self.hash_file, 'w') as f:
            f.write('#include <Python.h>\n')
            f.write('#include <structmember.h>\n')
            headers = set()
            for h in hashdata:
                headers.update(set(h['headers']))
            for header in sorted(headers):   
                f.write('#include <nettle/{}>\n'.format(header))
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
            f.write('\n')

            for c in ciphers:
                for mode in c['modes']:
                    objname = '{}_{}'.format(c['name'], mode)
                    cipherclass = Cipher(c['name'], c['family'], mode,
                                         c['docstring'])
                    cipherclass.write_to_file(f)
                    self.objects.append(objname)
                
    def gen_mod_file(self):
        with open(self.mod_file, 'w') as f:
            f.write('#include <Python.h>\n')
            for object in sorted(self.objects):
                f.write('extern PyTypeObject pynettle_{}_Type;\n'.format(object))

            module = CModule(name='nettle', objects=self.objects)
            module.write_to_file(f)

gen = Generator()
gen.gen_hash_file(hashes)
gen.gen_cipher_file(ciphers)
gen.gen_mod_file()
