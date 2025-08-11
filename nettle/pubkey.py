import _nettle
from .autogen import ASN1Error
import base64
import io
import re


class RSAKeyPair (_nettle.RSAKeyPair):
    def __init__(self, *args, **kwargs):
        _nettle.RSAKeyPair.__init__(self, *args, **kwargs)

    def read_key(self, filename):
        with open(filename, 'rb') as f:
            first = bytes(f.read(1))[0]
            if first == 0x30 or first == '0':
                pem = False
            else:
                pem = True
        if pem:
            with open(filename, encoding='ascii') as f:
                data = f.read()
                m = re.search(r'^-----BEGIN ([^-]+)-----$'
                              '^([^-]+)$'
                              '^-----END[^-]+-----$',
                              data, re.M)
                if m:
                    keytype = m.group(1)
                    b64 = m.group(2)
                    if keytype == 'RSA PRIVATE KEY':
                        self.read_pkcs1_key(base64.b64decode(b64))
                    elif keytype == 'PRIVATE KEY':
                        self.read_pkcs8_key(base64.b64decode(b64))
                    else:
                        raise NotImplemented
        else:
            with open(filename, 'rb') as f:
                data = f.read()
                try:
                    self.from_pkcs1(data)
                except ASN1Error:
                    self.from_pkcs8(data)

    def write_key(self, filename):
        buf = self.to_pkcs1_key()
        with open(filename, 'wb') as f:
            f.write(buf)


class RSAPubKey (_nettle.RSAPubKey):
    def __init__(self, *args, **kwargs):
        _nettle.RSAPubKey.__init__(self, *args, **kwargs)

    def read_key(self, filename):
        with open(filename, 'rb') as f:
            first = bytes(f.read(1))[0]
            if first == 0x30 or first == '0':
                pem = False
            else:
                pem = True
        if pem:
            with io.open(filename, encoding='ascii') as f:
                data = f.read()
                m = re.search(r'^-----BEGIN ([^-]+)-----$'
                              '([^-]+)'
                              '^-----END[^-]+-----$',
                              data, re.MULTILINE)
                if m:
                    keytype = m.group(1)
                    b64 = m.group(2)
                    if keytype == 'RSA PUBLIC KEY':
                        self.from_pkcs1(base64.b64decode(b64))
                    elif keytype == 'PUBLIC KEY':
                        self.from_pkcs8(base64.b64decode(b64))
                    elif keytype == 'CERTIFICATE':
                        self.from_cert(base64.b64decode(b64))
                    else:
                        raise NotImplemented
        else:
            with open(filename, 'rb') as f:
                data = f.read()
                try:
                    self.from_pkcs1(data)
                except ASN1Error:
                    self.from_pkcs8(data)

    def write_key(self, filename):
        buf = self.to_pkcs8_key()
        with open(filename, 'wb') as f:
            f.write(buf)
