from unittest import TestCase
import nettle
import sys
import os


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
        del pk2

        cleartext = b'Urtica dioica'
        ciphertext = pk.encrypt(cleartext)
        decrypted = kp.decrypt(ciphertext)
        self.assertEqual(cleartext, decrypted)

        cleartext = b'Urtica dioica'
        ciphertext = kp.encrypt(cleartext)
        decrypted = kp.decrypt(ciphertext)
        self.assertEqual(cleartext, decrypted)

        h = nettle.sha256()
        h.update(cleartext)
        signature = kp.sign(h)
        h2 = nettle.sha256()
        h2.update(cleartext)
        self.assertTrue(pk.verify(signature, h2))
        h2.update(b'gibberish')
        self.assertFalse(pk.verify(signature, h2))

        yarrow = nettle.Yarrow()
        pk = pubkey(yarrow)

    def test_rsa(self):
        self._test(nettle.RSAKeyPair, nettle.RSAPubKey)
