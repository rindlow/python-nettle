from unittest import TestCase
import nettle
import sys
import os

def SDATA(string):
    return string.encode('ascii')


def SHEX(hexstring):
    # return bytes.fromhex(hexstring) #Python 3 only. :-(
    b = bytearray()
    hexstring = ''.join(hexstring.split())
    for i in range(0, len(hexstring), 2):
        b.append(int(hexstring[i:i+2], 16))
    return bytes(b)


class PubKey(TestCase):

    def _test(self, keypair, pubkey):
        privfile = '/tmp/privkey.der'
        pubfile = '/tmp/pubkey.der'

        kp = keypair()
        kp.genkey(2048, 20)
        kp.save_key(privfile)
        kp2 = keypair()
        kp2.read_key(privfile)
        self.assertEqual(kp, kp2)
        del kp2

        pk = kp.public_key
        pk.save_key(pubfile)
        pk2 = pubkey()
        pk2.read_key(pubfile)
        self.assertEqual(pk, pk2)

        cleartext = b'Urtica dioica'
        ciphertext = pk.encrypt(cleartext)
        decrypted = kp.decrypt(ciphertext)
        self.assertEqual(cleartext, decrypted)
        
    def test_rsa(self):
        self._test(nettle.RSAKeyPair, nettle.RSAPubKey)
