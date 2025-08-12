from unittest import TestCase
import nettle


class PubKey(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.yarrow = nettle.Yarrow()
        cls.keypair = nettle.RSAKeyPair(cls.yarrow)
        cls.keypair.genkey(2048, 20)

    @classmethod
    def tearDownClass(cls):
        del cls.keypair
        del cls.yarrow

    def test_read_write(self):
        privfile = '/tmp/privkey.der'
        pubfile = '/tmp/pubkey.der'

        kp = self.keypair

        kp.write_key(privfile)
        kp2 = nettle.RSAKeyPair(self.yarrow)
        kp2.read_key(privfile)
        self.assertEqual(kp, kp2)
        del kp2

        pk = kp.public_key
        pk.write_key(pubfile)
        pk2 = nettle.RSAPubKey(self.yarrow)
        pk2.read_key(pubfile)
        self.assertEqual(pk, pk2)
        del pk2

    def test_encrypt_decrypt(self):

        kp = self.keypair
        pk = kp.public_key
        cleartext = b'Urtica dioica'

        ciphertext = pk.encrypt(cleartext)
        decrypted = kp.decrypt(ciphertext)
        self.assertEqual(cleartext, decrypted)

        ciphertext = kp.encrypt(cleartext)
        decrypted = kp.decrypt(ciphertext)
        self.assertEqual(cleartext, decrypted)

        with self.assertRaises(nettle.RSAError):
            cleartext = b'\00' * (pk.size)
            ciphertext = pk.encrypt(cleartext)


    def test_sign_verify(self):

        kp = self.keypair
        pk = kp.public_key
        cleartext = b'Urtica dioica'

        h = nettle.sha256()
        h.update(cleartext)
        signature = kp.sign(h)
        h2 = nettle.sha256()
        h2.update(cleartext)
        self.assertTrue(pk.verify(signature, h2))
        h2.update(b'gibberish')
        self.assertFalse(pk.verify(signature, h2))

    def test_yarrow(self):
        kp = self.keypair

        self.assertNotEqual(kp.yarrow.random(1), b'17')

    def test_oaep_encrypt_decrypt(self):

        kp = self.keypair
        pk = kp.public_key
        cleartext = b'Urtica dioica'

        ciphertext = pk.oaep_sha256_encrypt(cleartext)
        decrypted = kp.oaep_sha256_decrypt(ciphertext)
        self.assertEqual(cleartext, decrypted)

        ciphertext_label = pk.oaep_sha256_encrypt(cleartext, label=b'Nettle')
        decrypted = kp.oaep_sha256_decrypt(ciphertext_label, label=b'Nettle')
        self.assertEqual(cleartext, decrypted)
        self.assertNotEqual(ciphertext, ciphertext_label)

        longmessage = b'x' * 300
        with self.assertRaises(nettle.RSAError):
            ciphertext = pk.oaep_sha256_encrypt(longmessage)

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
        self.assertEqual(pub.size, 256)

    def test_kp_params(self):
        kp = nettle.RSAKeyPair()
        kp.from_params(
            n=bytes.fromhex(
                "69abd505285af66536ddc7c8f027e6f0ed435d6748b16088"
                "4fd60842b3a8d7fbbd8a3c98f0cc50ae4f6a9f7dd73122cc"
                "ec8afa3f77134406f53721973115fc2d8cfbba23b145f28d"
                "84f81d3b6ae8ce1e2850580c026e809bcfbb52566ea3a3b3"
                "df7edf52971872a7e35c1451b8636d22279a8fb299368238"
                "e545fbb4cf"),
            e=bytes.fromhex("0db2ad57"),
            d=bytes.fromhex(
                "3240a56f4cd0dcc24a413eb4ea5452595c83d771a1c2ba7b"
                "ec47c5b43eb4b37409bd2aa1e236dd86481eb1768811412f"
                "f8d91be3545912afb55c014cb55ceac654216af3b85d5c4f"
                "4a32894e3b5dfcde5b2875aa4dc8d9a86afd0ca92ef50d35"
                "bd09f1c47efb4c8dc631e07698d362aa4a83fd304e66d6c5"
                "468863c307"),
            p=bytes.fromhex(
                "0a66399919be4b4de5a78c5ea5c85bf9aba8c013cb4a8732"
                "14557a12bd67711ebb4073fd39ad9a86f4e80253ad809e5b"
                "f2fad3bc37f6f013273c9552c9f489"),
            q=bytes.fromhex(
                "0a294f069f118625f5eae2538db9338c776a298eae953329"
                "9fd1eed4eba04e82b2593bc98ba8db27de034da7daaea795"
                "2d55b07b5f9a5875d1ca5f6dcab897"),
            a=bytes.fromhex(
                "011b6c48eb592eeee85d1bb35cfb6e07344ea0b5e5f03a28"
                "5b405396cbc78c5c868e961db160ba8d4b984250930cf79a"
                "1bf8a9f28963de53128aa7d690eb87"),
            b=bytes.fromhex(
                "0409ecf3d2557c88214f1af5e1f17853d8b2d63782fa5628"
                "60cf579b0833b7ff5c0529f2a97c64522fa1a8878a9635ab"
                "ce56debf431bdec270b308fa5bf387"),
            c=bytes.fromhex(
                "04e103ee925cb5e66653949fa5e1a462c9e65e1adcd60058"
                "e2df9607cee95fa8daec7a389a7d9afc8dd21fef9d83805a"
                "40d46f49676a2f6b2926f70c572c00"))
        self.assertEqual(kp.size, 125)

    def test_pk_params(self):
        pk = nettle.RSAPubKey()
        pk.from_params(
            n=bytes.fromhex(
                "69abd505285af66536ddc7c8f027e6f0ed435d6748b16088"
                "4fd60842b3a8d7fbbd8a3c98f0cc50ae4f6a9f7dd73122cc"
                "ec8afa3f77134406f53721973115fc2d8cfbba23b145f28d"
                "84f81d3b6ae8ce1e2850580c026e809bcfbb52566ea3a3b3"
                "df7edf52971872a7e35c1451b8636d22279a8fb299368238"
                "e545fbb4cf"),
            e=bytes.fromhex("0db2ad57"))
        self.assertEqual(pk.size, 125)
