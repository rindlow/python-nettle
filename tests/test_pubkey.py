from unittest import TestCase
import nettle


class PubKey(TestCase):

    def _test(self, keypair, pubkey):
        privfile = '/tmp/privkey.der'
        pubfile = '/tmp/pubkey.der'

        kp = keypair()
        kp.genkey(2048, 20)
        kp.write_key(privfile)
        kp2 = keypair()
        kp2.read_key(privfile)
        self.assertEqual(kp, kp2)
        del kp2

        pk = kp.public_key
        pk.write_key(pubfile)
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

        kp.yarrow.random(1)

    def test_rsa(self):
        self._test(nettle.RSAKeyPair, nettle.RSAPubKey)

    def test_yarrow(self):
        yarrow = nettle.Yarrow()
        return yarrow.random(1)

    def test_cert(self):
        certfile = '/tmp/cert.pem'
        with open(certfile, 'w') as f:
            f.write('''-----BEGIN CERTIFICATE-----
MIIFAjCCA+qgAwIBAgIRAIE9FoMy9cOOUjm9JU/55wswDQYJKoZIhvcNAQEFBQAw
czELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxGTAXBgNV
BAMTEFBvc2l0aXZlU1NMIENBIDIwHhcNMTMwODEyMDAwMDAwWhcNMTgwODExMjM1
OTU5WjBTMSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0ZWQxFDASBgNV
BAsTC1Bvc2l0aXZlU1NMMRgwFgYDVQQDEw9tdXBwLm5ldGNhbXAuc2UwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDH6PsKVWdTdr93gmYIkgh6MO0s10M7
1nf5Biup6pnP3EOsqSdwt2jgAFI/vGpX9q/KACDeJ8IF5THh/9Jk5dcD2/9oi8Sa
2VtZBnQGwqofwyMoUApocglCrYhWbZVBzD075h4I3io483BELl6tMD00EouWcZqz
b1moD46HklcfJoXxcV0WJuicStzAZdbL+CGj78VrrfN+2JKrHZrGAK9AjsPJ+zN8
Yn9olMsnBrBT844+YqG5uEuxx4grb02vs/mf4AMbxkelBCyKTsGYdCpBYC7oVvGy
wbYyXtpbbyNPcPSwPqiUS8urzkHt29HQ3S+Ng5ypBTrupKmFdP8ZqcGXAgMBAAGj
ggGvMIIBqzAfBgNVHSMEGDAWgBSZ5EBfaxRePgXZ3dNjVPxiuPcArDAdBgNVHQ4E
FgQUo64YW2kKHbPuy7Hio4dxxtqGLZcwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB
/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMFAGA1UdIARJMEcw
OwYLKwYBBAGyMQECAgcwLDAqBggrBgEFBQcCARYeaHR0cDovL3d3dy5wb3NpdGl2
ZXNzbC5jb20vQ1BTMAgGBmeBDAECATA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8v
Y3JsLmNvbW9kb2NhLmNvbS9Qb3NpdGl2ZVNTTENBMi5jcmwwbAYIKwYBBQUHAQEE
YDBeMDYGCCsGAQUFBzAChipodHRwOi8vY3J0LmNvbW9kb2NhLmNvbS9Qb3NpdGl2
ZVNTTENBMi5jcnQwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNv
bTAvBgNVHREEKDAmgg9tdXBwLm5ldGNhbXAuc2WCE3d3dy5tdXBwLm5ldGNhbXAu
c2UwDQYJKoZIhvcNAQEFBQADggEBAA757IeJJvDxvUcDnMRLb1ELud3UNCS9nFn5
H8m/FDOTr7jJaOO1bE5fG6SK7o71WEuT9N3EbAXtIk7lpLYWqQe4G0D8wwTVVBaS
JgJH2f0bSlkHi9g2e+fcDH/Y8XGvRIoUrvndBcmPtfCn38DushHNOr31i4rKl48n
sgoN3A1+OUpbjGR6v9crxp3zGNrNHjDonlw+WByIAB627+Vmzz8gK5/D6e7O0h99
elkmpGICXFrPJ0rPsX6w3NV1vFU8X9+bPkHG7GOh0GTMn+JqOsHI+858RQYXxg5x
aClfUZqTLvQwUMIWydXnDTuHedumUwbq40X7z9krch7Agys+KLA=
-----END CERTIFICATE-----''')
        pub = nettle.RSAPubKey()
        pub.read_key(certfile)
