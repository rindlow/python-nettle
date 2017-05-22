#!/usr/bin/env python3

import nettle.hash
s1 = nettle.hash.sha1()
s1.update(b'')
if s1.digest() == b'\xDA\x39\xA3\xEE\x5E\x6B\x4B\x0D\x32\x55\xBF\xEF\x95\x60\x18\x90\xAF\xD8\x07\x09':
    print('sha1\tok')
else:
    print('sha1\tfail')
print(s1.digest_size, s1.block_size)
del s1

s2 = nettle.hash.sha256()
s2.update(b'')
if s2.digest() == b'\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55':
    print('sha256\tok')
else:
    print('sha256\tfail')
del s2

