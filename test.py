#!/usr/bin/env python3

import nettle
s1 = nettle.sha1()
s1.update(b'')
if s1.digest() == b'\xDA\x39\xA3\xEE\x5E\x6B\x4B\x0D' \
   b'\x32\x55\xBF\xEF\x95\x60\x18\x90\xAF\xD8\x07\x09':
    print('sha1\tok')
else:
    print('sha1\tfail')
print(s1.digest_size, s1.block_size)
del s1

s2 = nettle.sha256()
s3 = nettle.sha256()
s3.update(b'foobar')
s2.update(b'')
if s2.digest() == b'\xe3\xb0\xc4\x42\x98\xfc\x1c\x14' \
   b'\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24' \
   b'\x27\xae\x41\xe4\x64\x9b\x93\x4c' \
   b'\xa4\x95\x99\x1b\x78\x52\xb8\x55':
    print('sha256\tok')
else:
    print('sha256\tfail')

key = b'\x00\x01\x02\x03\x05\x06\x07\x08\x0A\x0B\x0C\x0D\x0F\x10\x11\x12'
clr = b'\x50\x68\x12\xA4\x5F\x08\xC8\x89\xB9\x7F\x59\x80\x03\x8B\x83\x59'
cry = b'\xD8\xF5\x32\x53\x82\x89\xEF\x7D\x06\xB5\x06\xA4\xFD\x5B\xE9\xC9'
a = nettle.aes128_ecb()
a.set_encrypt_key(key)
if a.encrypt(clr) == cry:
    print('aes128 encrypt\tok')
else:
    print('aes128 encrypt\tfail')
a.invert_key()
if a.decrypt(cry) == clr:
    print('aes128 decrypt\tok')
else:
    print('aes128 decrypt\tfail')
del a
a = nettle.aes128_ecb(encrypt_key=key)
if a.encrypt(clr) == cry:
    print('aes128 encrypt\tok')
else:
    print('aes128 encrypt\tfail')


a = nettle.aes128_cbc(encrypt_key=key, iv=b'\0' * 16)
a.encrypt(clr)
