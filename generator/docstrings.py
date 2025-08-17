# -*- coding: utf-8 -*-
#
# docstrings.py
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

# Hashes

gosthash94 = 'The GOST94 or GOST R 34.11-94 hash algorithm is a Soviet-era' \
    ' algorithm used in Russian government standards (see RFC 4357). It' \
    ' outputs message digests of 256 bits, or 32 octets.'

md2 = 'MD2 is another hash function of Ronald Rivest’s, described in RFC' \
    ' 1319. It outputs message digests of 128 bits, or 16 octets.'

md4 = 'MD4 is a predecessor of MD5, described in RFC 1320. Like MD5, it is' \
    ' constructed by Ronald Rivest. It outputs message digests of 128 bits,' \
    ' or 16 octets. Use of MD4 is not recommended, but it is sometimes' \
    ' needed for compatibility with existing applications and protocols.'

md5 = 'MD5 is a message digest function constructed by Ronald Rivest, and' \
    ' described in RFC 1321. It outputs message digests of 128 bits, or 16' \
    ' octets.'

ripemd160 = 'RIPEMD160 is a hash function designed by Hans Dobbertin,' \
    ' Antoon Bosselaers, and Bart Preneel, as a strengthened version of' \
    ' RIPEMD (which, like MD4 and MD5, fails the collision-resistance' \
    ' requirement). It produces message digests of 160 bits, or 20 octets.'

sha1 = 'SHA1 is a hash function specified by NIST (The U.S.' \
    ' National Institute for Standards and Technology).'

sha224 = 'SHA224 is a variant of SHA256, with a different initial' \
    ' state, and with the output truncated to 224 bits, or 28 octets.'

sha256 = 'SHA256 is a member of the SHA2 family. It outputs hash' \
    ' values of 256 bits, or 32 octets.'

sha512 = 'SHA512 is a larger sibling to SHA256, with a very' \
    ' similar structure but with both the output and the internal' \
    ' variables of twice the size. The internal variables are 64 bits' \
    ' rather than 32, making it significantly slower on 32-bit computers.' \
    ' It outputs hash values of 512 bits, or 64 octets.'

sha384 = 'Several variants of SHA512 have been defined, with a different' \
    ' initial state, and with the output truncated to shorter length than' \
    ' 512 bits. Naming is a bit confused, these algorithms are called' \
    ' SHA512-224, SHA512-256 and SHA384, for output sizes of 224, 256 and' \
    ' 384 bits, respectively.'

sha3_224 = 'The SHA3 hash functions were specified by NIST in response to' \
    ' weaknesses in SHA1, and doubts about SHA2 hash functions which' \
    ' structurally are very similar to SHA1. SHA3 is a result of a' \
    ' competition, where the winner, also known as Keccak, was designed by' \
    ' Guido Bertoni, Joan Daemen, MichaÃ«l Peeters and Gilles Van Assche.' \
    ' It is structurally very different from all widely used earlier hash' \
    ' functions. Like SHA2, there are several variants, with output sizes' \
    ' of 224, 256, 384 and 512 bits (28, 32, 48 and 64 octets,' \
    ' respectively). In August 2015, it was formally standardized by NIST,' \
    ' as FIPS 202, http://dx.doi.org/10.6028/NIST.FIPS.202.'

sha3_256 = 'This is SHA3 with 256-bit output size, and possibly the most' \
    ' useful of the SHA3 hash functions.'

sha3_384 = 'This is SHA3 with 384-bit output size.'

sha3_512 = 'This is SHA3 with 512-bit output size.'

streebog_512 = 'STREEBOG512 is a member of the Streebog (GOST R 34.11-2012)'\
    ' family. It outputs hash values of 512 bits, or 64 octets.'

streebog_256 = 'STREEBOG256 is a variant of STREEBOG512, with a different'\
    ' initial state, and with the output truncated to 256 bits, or 32 octets.'

sm3 = 'SM3 is a cryptographic hash function standard adopted by the'\
    ' government of the People’s Republic of China, which was issued by the'\
    ' Cryptography Standardization Technical Committee of China on December'\
    ' 17, 2010. The corresponding standard is GM/T 0004-2012 \\"SM3'\
    ' Cryptographic Hash Algorithm\\".'

# Ciphers

aes = 'AES is a block cipher, specified by NIST as a replacement' \
    ' for the older DES standard. The standard is the result of a' \
    ' competition between cipher designers. The winning design, also known' \
    ' as RIJNDAEL, was constructed by Joan Daemen and Vincent Rijnmen.' \
    ' Like all the AES candidates, the winning design uses a block size of' \
    ' 128 bits, or 16 octets, and three possible key-size, 128, 192 and 256' \
    ' bits (16, 24 and 32 octets) being the allowed key sizes. It does not' \
    ' have any weak keys.'

camellia = 'Camellia is a block cipher developed by Mitsubishi and' \
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

arcfour = 'ARCFOUR is a stream cipher, also known under the trade marked' \
    'name RC4, and it is one of the fastest ciphers around. A' \
    ' problem is that the key setup of ARCFOUR is quite weak, you should' \
    ' never use keys with structure, keys that are ordinary' \
    ' passwords, or sequences of keys like \\"secret:1\\", \\"secret:2\\"' \
    ' .... If you have keys that don\'t look like random bit strings,' \
    ' and you want to use ARCFOUR, always hash the key before feeding' \
    ' it to ARCFOUR. Furthermore, the initial bytes of the generated' \
    ' key stream leak information about the key; for this reason, it' \
    ' is recommended to discard the first 512 bytes of the key' \
    ' stream.'

arctwo = 'ARCTWO (also known as the trade marked name RC2) is a block' \
    ' cipher specified in RFC 2268. Nettle also include a variation of' \
    ' the ARCTWO set key operation that lack one step, to be compatible' \
    ' with the reverse engineered RC2 cipher description, as described in' \
    ' a Usenet post to sci.crypt by Peter Gutmann. We do not recommend the' \
    ' use of ARCTWO; the Nettle implementation is provided primarily for' \
    ' interoperability with existing applications and standards.'

blowfish = 'BLOWFISH is a block cipher designed by Bruce Schneier. It uses' \
    ' a block size of 64 bits (8 octets), and a variable key size, up to' \
    ' 448 bits. It has some weak keys. '

cast128 = 'CAST-128 is a block cipher, specified in RFC 2144. It uses a 64' \
    ' bit (8 octets) block size, and a variable key size of up to 128 bits. '

chacha = 'ChaCha is a variant of the stream cipher Salsa20. When using' \
    ' ChaCha to process a message, one specifies both a key and a' \
    ' nonce, the latter playing a similar role to the initialization' \
    ' vector (IV) used with CBC or CTR mode. One can use the same key' \
    ' for several messages, provided one uses a unique random nonce for' \
    ' each message. The nonce is 64 bits (8 octets). The block counter' \
    ' is initialized to zero for each message, and is also 64 bits (8 octets).'

salsa20 = 'When using' \
    ' salsa20 to process a message, one specifies both a key and a' \
    ' nonce, the latter playing a similar role to the initialization' \
    ' vector (IV) used with CBC or CTR mode. One can use the same key' \
    ' for several messages, provided one uses a unique random nonce for' \
    ' each message. The nonce is 64 bits (8 octets). The block counter' \
    ' is initialized to zero for each message, and is also 64 bits (8 octets).'

des = 'DES is the old Data Encryption Standard, specified by NIST. It uses' \
    ' a block size of 64 bits (8 octets), and a key size of 56 bits.' \
    ' However, the key bits are distributed over 8 octets, where the least' \
    ' significant bit of each octet may be used for parity. A common way to' \
    ' use DES is to generate 8 random octets in some way, then set the least' \
    ' significant bit of each octet to get odd parity, and initialize DES' \
    ' with the resulting key. The key size of DES is so small that keys can' \
    ' be found by brute force, using specialized hardware or lots of' \
    ' ordinary work stations in parallel. One shouldn’t be using plain DES' \
    ' at all today, if one uses DES at all one should be using \\"triple' \
    ' DES\\", see DES3 below. '

des3 = 'The standard way to increase DES’s key size is to use three DES' \
    ' boxes. The mode of operation is a little peculiar: the middle DES' \
    ' box is wired in the reverse direction. To encrypt a block with DES3,' \
    ' you encrypt it using the first 56 bits of the key, then decrypt it' \
    ' using the middle 56 bits of the key, and finally encrypt it again' \
    ' using the last 56 bits of the key. This is known as \\"ede\\"' \
    ' triple-DES, for \\"encrypt-decrypt-encrypt\\". The \\"ede\\"' \
    ' construction provides some backward compatibility, as you get plain' \
    ' single DES simply by feeding the same key to all three boxes. That' \
    ' should help keeping down the gate count, and the price, of hardware' \
    ' circuits implementing both plain DES and DES3. DES3 has a key size' \
    ' of 168 bits, but just like plain DES, useless parity bits are' \
    ' inserted, so that keys are represented as 24 octets (192 bits). As' \
    ' a 112 bit key is large enough to make brute force attacks impractical,' \
    ' some applications uses a \\"two-key\\" variant of triple-DES. In this' \
    ' mode, the same key bits are used for the first and the last DES box' \
    ' in the pipe, while the middle box is keyed independently. The two-key' \
    ' variant is believed to be secure, i.e. there are no known attacks' \
    ' significantly better than brute force.'

serpent = 'SERPENT is one of the AES finalists, designed by Ross' \
    ' Anderson, Eli Biham and Lars Knudsen. Thus, the interface and' \
    ' properties are similar to AES\'. One peculiarity is that it is' \
    ' quite pointless to use it with anything but the maximum key size,' \
    ' smaller keys are just padded to larger ones.'

sm4 = 'SM4 is a block cipher standard adopted by the government of the' \
    ' People’s Republic of China, and it was issued by the State' \
    ' Cryptography Administration on March 21, 2012. The standard is GM/T' \
    ' 0002-2012 \\"SM4 block cipher algorithm\\".'

twofish = 'Another AES finalist, this one designed by Bruce Schneier ' \
    'and others.'

# MACs

hmac = 'For an underlying hash function H, with digest size l and' \
    ' internalblock size b, HMAC-H is constructed as follows: From a' \
    ' given key k, two distinct subkeys k_i and k_o are constructed,' \
    ' both of length b. The HMAC-H of a message m is then computed as' \
    ' H(k_o | H(k_i | m)), where | denotes string concatenation. HMAC' \
    ' keys can be of any length, but it is recommended to use keys of' \
    ' length l, the digest size of the underlying hash function H.' \
    ' Keys that are longer than b are shortened to length l by hashing' \
    ' with H, so arbitrarily long keys aren\'t very useful.'

umac = 'UMAC is a message authentication code based on universal' \
    ' hashing, and designed for high performance on modern processors (in' \
    ' contrast to GCM, See GCM, which is designed primarily for' \
    ' hardware performance). On processors with good integer' \
    ' multiplication performance, it can be 10 times faster than' \
    ' SHA256 and SHA512. UMAC is specified in RFC 4418. The secret key' \
    ' is always 128 bits (16 octets). The key is used as an encryption' \
    ' key for the AES block cipher. This cipher is used in counter' \
    ' mode to generate various internal subkeys needed in UMAC.' \
    ' Messages are of arbitrary size, and for each message, UMAC also' \
    ' needs a unique nonce. Nonce values must not be reused for two' \
    ' messages with the same key, but they need not be kept secret.' \
    ' The nonce must be at least one octet, and at most 16; nonces' \
    ' shorter than 16 octets are zero-padded. Nettle\'s implementation' \
    ' of UMAC increments the nonce automatically for each message, so' \
    ' explicitly setting the nonce for each message is optional. This' \
    ' auto-increment uses network byte order and it takes the length' \
    ' of the nonce into account. E.g., if the initial nonce is \\"abc\\"' \
    ' (3 octets), this value is zero-padded to 16 octets for the first' \
    ' message. For the next message, the nonce is incremented to' \
    ' \\"abd\\", and this incremented value is zero-padded to 16 octets.' \
    ' UMAC is defined in four variants, for different output sizes: 32' \
    ' bits (4 octets), 64 bits (8 octets), 96 bits (12 octets) and 128' \
    ' bits (16 octets), corresponding to different trade-offs between' \
    ' speed and security. Using a shorter output size sometimes (but' \
    ' not always!) gives the same result as using a longer output size' \
    ' and truncating the result. So it is important to use the right' \
    ' variant. For consistency with other hash and MAC functions,' \
    ' Nettle\'s _digest functions for UMAC accept a length parameter so' \
    ' that the output can be truncated to any desired size, but it is' \
    ' recommended to stick to the specified output size and select the' \
    ' umac variant corresponding to the desired size. The internal' \
    ' block size of UMAC is 1024 octets, and it also generates more' \
    ' than 1024 bytes of subkeys. This makes the size of the context' \
    ' struct quite a bit larger than other hash functions and MAC' \
    ' algorithms in Nettle.'

poly1305 = 'Poly1305-AES is a message authentication code designed by' \
    ' D. J. Bernstein. It treats the message as a polynomial modulo the' \
    ' prime number 2^130 - 5. The key, 256 bits, consists of two parts,' \
    ' where the first half is an AES-128 key, and the second half specifies' \
    ' the point where the polynomial is evaluated. Of the latter half, 22' \
    ' bits are set to zero, to enable high-performance implementation,' \
    ' leaving 106 bits for specifying an evaluation point r. For each' \
    ' message, one must also provide a 128-bit nonce. The nonce is' \
    ' encrypted using the AES key, and that’s the only thing AES is used' \
    ' for. The message is split into 128-bit chunks (with final chunk' \
    ' possibly being shorter), each read as a little-endian integer. Each' \
    ' chunk has a one-bit appended at the high end. The resulting integers' \
    ' are treated as polynomial coefficients modulo 2^130 - 5, and the' \
    ' polynomial is evaluated at the point r. Finally, this value is' \
    ' reduced modulo 2^128, and added (also modulo 2^128) to the encrypted' \
    ' nonce, to produce an 128-bit authenticator for the message. See' \
    ' http://cr.yp.to/mac/poly1305-20050329.pdf for further details.'

hash_example = '''
   >>> import nettle
   >>> sha = nettle.sha256()
   >>> sha.update(b'abc')
   >>> sha.hexdigest()
   'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD'
   >>> nettle.sha256(b'abc').digest()
   b'\\xbax\\x16\\xbf\\x8f\\x01\\xcf\\xeaAA@\\xde]\\xae"#\\xb0\\x03a\\xa3''' \
+ '''\\x96\\x17z\\x9c\\xb4\\x10\\xffa\\xf2\\x00\\x15\\xad'
   >>> nettle.sha256(b'abc').hexdigest()
   'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD'
'''

# noinspection PyPep8
cipher_example = '''
   >>> import nettle
   >>> encryptor = nettle.aes128(encrypt_key=b'\\x00\\x01\\x02\\x03\\x05''' \
+ '''\\x06\\x07\\x08\\n\\x0b\\x0c\\r\\x0f\\x10\\x11\\x12')
   >>> decryptor = nettle.aes128(decrypt_key=b'\\x00\\x01\\x02\\x03\\x05''' \
+ '''\\x06\\x07\\x08\\n\\x0b\\x0c\\r\\x0f\\x10\\x11\\x12')
   >>> encryptor.encrypt(b'Secret Message!\\0')
   b'\\x1a\\xcb8,}!\\x0f\\xa7\\x80\\xbb\\xd8e\\x98.\\x93\\x04'
   >>> decryptor.decrypt(b'\\x1a\\xcb8,}!\\x0f\\xa7\\x80\\xbb\\xd8e\\x98''' \
+ '''.\\x93\\x04')
   b'Secret Message!\\x00'
'''

mac_example = '''
   >>> import nettle
   >>> hmac = nettle.hmac_sha256(b'Secret key')
   >>> hmac.update(b'Hi There!')
   >>> hmac.hexdigest()
   '17194E73033A1BED403216150E8DA0CA1D0772C2F5A7A1BF36CB72D7173A4980'
'''

ciphermode_example = '''
   >>> import nettle
   >>> encryptor = nettle.aes128(encrypt_key=b'\\x00\\x01\\x02\\x03\\x05''' \
+ '''\\x06\\x07\\x08\\n\\x0b\\x0c\\r\\x0f\\x10\\x11\\x12')
   >>> cbc = nettle.CBC(encryptor, b'abababababababab')
   >>> cbc.encrypt(b'Secret Message!\\0')
   b'\\x94O,\\xed\\xae\\xc0\\x82\\xe1\\x8c\\xb0-\\xca\\xf7\\xdb\\x8a\\xfd'
   >>> decryptor = nettle.aes128(decrypt_key=b'\\x00\\x01\\x02\\x03\\x05''' \
+ '''\\x06\\x07\\x08\\n\\x0b\\x0c\\r\\x0f\\x10\\x11\\x12')
   >>> cbc = nettle.CBC(decryptor, b'abababababababab')
   >>> cbc.decrypt(b'\\x94O,\\xed\\xae\\xc0\\x82\\xe1\\x8c\\xb0-\\xca\\xf7''' \
+ '''\\xdb\\x8a\\xfd')
   b'Secret Message!\\x00'
'''

pubkey_example = '''
   >>> import nettle
   >>> keypair = nettle.RSAKeyPair()
   >>> keypair.genkey(2048, 20)
   >>> pubkey = keypair.public_key
   >>> ciphertext = pubkey.encrypt(b'Secret Message!')
   >>> keypair.decrypt(ciphertext)
   b'Secret Message!'
   >>> hash = nettle.sha256(b'Data to be signed')
   >>> signature = keypair.sign(hash)
   >>> pubkey.verify(signature, nettle.sha256(b'Data to be signed'))
   True
'''
