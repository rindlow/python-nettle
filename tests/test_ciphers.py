from unittest import TestCase
import nettle
import sys


def SHEX(hexstring):
    # return bytes.fromhex(hexstring) #Python 3 only. :-(
    b = bytearray()
    hexstring = ''.join(hexstring.split())
    for i in range(0, len(hexstring), 2):
        b.append(int(hexstring[i:i+2], 16))
    return bytes(b)


class AES_ECB(TestCase):

    def _test(self, cipher, key, cleartext, ciphertext):
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher()
        self.assertEqual(len(key), c.key_size)
        c.set_encrypt_key(key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        c.set_decrypt_key(key)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

        c = cipher(encrypt_key=key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        c = cipher(decrypt_key=key)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

    def test_aes128_ecb(self):
        self._test(nettle.aes128_ecb,
                   SHEX("0001020305060708 0A0B0C0D0F101112"),
                   SHEX("506812A45F08C889 B97F5980038B8359"),
                   SHEX("D8F532538289EF7D 06B506A4FD5BE9C9"))

    def test_aes192_ecb(self):
        self._test(nettle.aes192_ecb,
                   SHEX("0001020305060708 0A0B0C0D0F101112"
                        "14151617191A1B1C"),
                   SHEX("2D33EEF2C0430A8A 9EBF45E809C40BB6"),
                   SHEX("DFF4945E0336DF4C 1C56BC700EFF837F"))

    def test_aes256_ecb(self):
        self._test(nettle.aes256_ecb,
                   SHEX("0001020305060708 0A0B0C0D0F101112"
                        "14151617191A1B1C 1E1F202123242526"),
                   SHEX("834EADFCCAC7E1B30664B1ABA44815AB"),
                   SHEX("1946DABF6A03A2A2 C3D0B05080AED6FC"))


class AES_CTR(TestCase):

    def _test(self, cipher, key, cleartext, ciphertext, ctr):
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher(encrypt_key=key, ctr=ctr)
        self.assertEqual(c.encrypt(cleartext), ciphertext)

    def test_aes128_ctr(self):
        self._test(nettle.aes128_ctr,
                   SHEX("2b7e151628aed2a6abf7158809cf4f3c"),
                   SHEX("6bc1bee22e409f96e93d7e117393172a"
                        "ae2d8a571e03ac9c9eb76fac45af8e51"
                        "30c81c46a35ce411e5fbc1191a0a52ef"
                        "f69f2445df4f9b17ad2b417be66c3710"),
                   SHEX("874d6191b620e3261bef6864990db6ce"
                        "9806f66b7970fdff8617187bb9fffdff"
                        "5ae4df3edbd5d35e5b4f09020db03eab"
                        "1e031dda2fbe03d1792170a0f3009cee"),
                   SHEX("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))

    def test_aes192_ctr(self):
        self._test(nettle.aes192_ctr,
                   SHEX("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
                   SHEX("6bc1bee22e409f96e93d7e117393172a"
                        "ae2d8a571e03ac9c9eb76fac45af8e51"
                        "30c81c46a35ce411e5fbc1191a0a52ef"
                        "f69f2445df4f9b17ad2b417be66c3710"),
                   SHEX("1abc932417521ca24f2b0459fe7e6e0b"
                        "090339ec0aa6faefd5ccc2c6f4ce8e94"
                        "1e36b26bd1ebc670d1bd1d665620abf7"
                        "4f78a7f6d29809585a97daec58c6b050"),
                   SHEX("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))

    def test_aes256_ctr(self):
        self._test(nettle.aes256_ctr,
                   SHEX("603deb1015ca71be2b73aef0857d7781"
                        "1f352c073b6108d72d9810a30914dff4"),
                   SHEX("6bc1bee22e409f96e93d7e117393172a"
                        "ae2d8a571e03ac9c9eb76fac45af8e51"
                        "30c81c46a35ce411e5fbc1191a0a52ef"
                        "f69f2445df4f9b17ad2b417be66c3710"),
                   SHEX("601ec313775789a5b7a7f504bbf3d228"
                        "f443e3ca4d62b59aca84e990cacaf5c5"
                        "2b0930daa23de94ce87017ba2d84988d"
                        "dfc9c58db67aada613c2dd08457941a6"),
                   SHEX("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))


class AES_CBC(TestCase):

    def _test(self, cipher, key, cleartext, ciphertext, iv):
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher(encrypt_key=key, iv=iv)
        self.assertEqual(c.encrypt(cleartext), ciphertext)

    def test_aes128_cbc(self):
        self._test(nettle.aes128_cbc,
                   SHEX("2b7e151628aed2a6abf7158809cf4f3c"),
                   SHEX("6bc1bee22e409f96e93d7e117393172a"
                        "ae2d8a571e03ac9c9eb76fac45af8e51"
                        "30c81c46a35ce411e5fbc1191a0a52ef"
                        "f69f2445df4f9b17ad2b417be66c3710"),
                   SHEX("7649abac8119b246cee98e9b12e9197d"
                        "5086cb9b507219ee95db113a917678b2"
                        "73bed6b8e3c1743b7116e69e22229516"
                        "3ff1caa1681fac09120eca307586e1a7"),
                   SHEX("000102030405060708090a0b0c0d0e0f"))

    def test_aes192_cbc(self):
        self._test(nettle.aes192_cbc,
                   SHEX("8e73b0f7da0e6452c810f32b809079e5"
                        "62f8ead2522c6b7b"),
                   SHEX("6bc1bee22e409f96e93d7e117393172a"
                        "ae2d8a571e03ac9c9eb76fac45af8e51"
                        "30c81c46a35ce411e5fbc1191a0a52ef"
                        "f69f2445df4f9b17ad2b417be66c3710"),
                   SHEX("4f021db243bc633d7178183a9fa071e8"
                        "b4d9ada9ad7dedf4e5e738763f69145a"
                        "571b242012fb7ae07fa9baac3df102e0"
                        "08b0e27988598881d920a9e64f5615cd"),
                   SHEX("000102030405060708090a0b0c0d0e0f"))

    def test_aes256_cbc(self):
        self._test(nettle.aes256_cbc,
                   SHEX("603deb1015ca71be2b73aef0857d7781"
                        "1f352c073b6108d72d9810a30914dff4"),
                   SHEX("6bc1bee22e409f96e93d7e117393172a"
                        "ae2d8a571e03ac9c9eb76fac45af8e51"
                        "30c81c46a35ce411e5fbc1191a0a52ef"
                        "f69f2445df4f9b17ad2b417be66c3710"),
                   SHEX("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                        "9cfc4e967edb808d679f777bc6702c7d"
                        "39f23369a9d9bacfa530e26304231461"
                        "b2eb05e2c39be9fcda6c19078c6a9d1b"),
                   SHEX("000102030405060708090a0b0c0d0e0f"))
