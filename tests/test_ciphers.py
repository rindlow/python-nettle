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

        with self.assertRaises(nettle.KeyLenError):
            c = cipher(encrypt_key=key[:-1])

        with self.assertRaises(nettle.NotInitializedError):
            c = cipher()
            c.encrypt(cleartext)
        
    def _test_invert(self, cipher, key, cleartext, ciphertext):
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher(encrypt_key=key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        c.invert_key()
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

    def test_aes128_ecb_invert(self):
        self._test_invert(nettle.aes128_ecb,
                          SHEX("0001020305060708 0A0B0C0D0F101112"),
                          SHEX("506812A45F08C889 B97F5980038B8359"),
                          SHEX("D8F532538289EF7D 06B506A4FD5BE9C9"))


class AES_CTR(TestCase):

    def _test(self, cipher, key, cleartext, ciphertext, ctr):
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher(encrypt_key=key, ctr=ctr)
        self.assertEqual(c.encrypt(cleartext), ciphertext)

        with self.assertRaises(nettle.KeyLenError):
            c = cipher(encrypt_key=key[:-1])

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

        with self.assertRaises(nettle.KeyLenError):
            c = cipher(encrypt_key=key[:-1])

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


class AES_GCM(TestCase):

    def _test(self, cipher, key, authtext, cleartext, ciphertext,
              iv, digest):
        self.assertEqual(len(cleartext), len(ciphertext))

        c = cipher()
        self.assertEqual(c.key_size, len(key))
        c.set_encrypt_key(key)
        c.set_iv(iv)
        c.update(authtext)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        self.assertEqual(c.digest(), digest)

        c = cipher(encrypt_key=key, iv=iv)
        c.update(authtext)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        self.assertEqual(c.digest(), digest)

        with self.assertRaises(nettle.KeyLenError):
            c = cipher(encrypt_key=key+b'a', iv=iv)
        
    def test_aes128_gcm(self):
        self._test(nettle.aes128_gcm,
                   SHEX("feffe9928665731c6d6a8f9467308308"),
                   SHEX("feedfacedeadbeeffeedfacedeadbeef"
                        "abaddad2"),
                   SHEX("d9313225f88406e5a55909c5aff5269a"
                        "86a7a9531534f7da2e4c303d8a318a72"
                        "1c3c0c95956809532fcf0e2449a6b525"
                        "b16aedf5aa0de657ba637b39"),
                   SHEX("42831ec2217774244b7221b784d0d49c"
                        "e3aa212f2c02a4e035c17e2329aca12e"
                        "21d514b25466931c7d8f6a5aac84aa05"
                        "1ba30b396a0aac973d58e091"),
                   SHEX("cafebabefacedbaddecaf888"),
                   SHEX("5bc94fbc3221a5db94fae95ae7121a47"))

    def test_aes192_gcm(self):
        self._test(nettle.aes192_gcm,
                   SHEX("feffe9928665731c6d6a8f9467308308"
                        "feffe9928665731c"),
                   SHEX("feedfacedeadbeeffeedfacedeadbeef"
                        "abaddad2"),
                   SHEX("d9313225f88406e5a55909c5aff5269a"
                        "86a7a9531534f7da2e4c303d8a318a72"
                        "1c3c0c95956809532fcf0e2449a6b525"
                        "b16aedf5aa0de657ba637b39"),
                   SHEX("3980ca0b3c00e841eb06fac4872a2757"
                        "859e1ceaa6efd984628593b40ca1e19c"
                        "7d773d00c144c525ac619d18c84a3f47"
                        "18e2448b2fe324d9ccda2710"),
                   SHEX("cafebabefacedbaddecaf888"),
                   SHEX("2519498e80f1478f37ba55bd6d27618c"))

    def test_aes256_gcm(self):
        self._test(nettle.aes256_gcm,
                   SHEX("feffe9928665731c6d6a8f9467308308"
                        "feffe9928665731c6d6a8f9467308308"),
                   SHEX("feedfacedeadbeeffeedfacedeadbeef"
                        "abaddad2"),
                   SHEX("d9313225f88406e5a55909c5aff5269a"
                        "86a7a9531534f7da2e4c303d8a318a72"
                        "1c3c0c95956809532fcf0e2449a6b525"
                        "b16aedf5aa0de657ba637b39"),
                   SHEX("522dc1f099567d07f47f37a32a84427d"
                        "643a8cdcbfe5c0c97598a2bd2555d1aa"
                        "8cb08e48590dbb3da7b08b1056828838"
                        "c5f61e6393ba7a0abcc9f662"),
                   SHEX("cafebabefacedbaddecaf888"),
                   SHEX("76fc6ece0f4e1768cddf8853bb2d551b"))


class Camellia_ECB(TestCase):

    def _test(self, cipher, key, cleartext, ciphertext):
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher()
        self.assertEqual(len(key), c.key_size)
        c.set_encrypt_key(key)
        self.assertEqual(c.crypt(cleartext), ciphertext)
        c.set_decrypt_key(key)
        self.assertEqual(c.crypt(ciphertext), cleartext)

        c = cipher(encrypt_key=key)
        self.assertEqual(c.crypt(cleartext), ciphertext)
        c = cipher(decrypt_key=key)
        self.assertEqual(c.crypt(ciphertext), cleartext)

        with self.assertRaises(nettle.KeyLenError):
            c = cipher(encrypt_key=key[:-1])
        
    def _test_invert(self, cipher, key, cleartext, ciphertext):
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher(encrypt_key=key)
        self.assertEqual(c.crypt(cleartext), ciphertext)
        c.invert_key()
        self.assertEqual(c.crypt(ciphertext), cleartext)

    def test_camellia128_ecb(self):
        self._test(nettle.camellia128_ecb,
                   SHEX("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
                   SHEX("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
                   SHEX("67 67 31 38 54 96 69 73 08 57 06 56 48 ea be 43"))

    def test_camellia192_ecb(self):
        self._test(nettle.camellia192_ecb,
                   SHEX("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
                        "00 11 22 33 44 55 66 77"),
                   SHEX("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
                   SHEX("b4 99 34 01 b3 e9 96 f8 4e e5 ce e7 d7 9b 09 b9"))

    def test_camellia256_ecb(self):
        self._test(nettle.camellia256_ecb,
                   SHEX("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
                        "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"),
                   SHEX("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
                   SHEX("9a cc 23 7d ff 16 d7 6c 20 ef 7c 91 9e 3a 75 09"))

    def test_camellia128_ecb_invert(self):
        self._test_invert(nettle.camellia128_ecb,
                          SHEX("01 23 45 67 89 ab cd ef"
                               "fe dc ba 98 76 54 32 10"),
                          SHEX("01 23 45 67 89 ab cd ef"
                               "fe dc ba 98 76 54 32 10"),
                          SHEX("67 67 31 38 54 96 69 73"
                               "08 57 06 56 48 ea be 43"))


class ARCFOUR(TestCase):

    def _test(self, key, cleartext, ciphertext):
        self.assertEqual(len(cleartext), len(ciphertext))
        c = nettle.arcfour()
        self.assertEqual(len(key), c.key_size)
        c.set_key(key)
        self.assertEqual(c.crypt(cleartext), ciphertext)
        c.set_key(key)
        self.assertEqual(c.crypt(ciphertext), cleartext)

        c = nettle.arcfour(key=key)
        self.assertEqual(c.crypt(cleartext), ciphertext)
        c = nettle.arcfour(key=key)
        self.assertEqual(c.crypt(ciphertext), cleartext)

        with self.assertRaises(nettle.KeyLenError):
            c = nettle.arcfour(key=key[:-1])

        with self.assertRaises(nettle.NotInitializedError):
            c = nettle.arcfour()
            c.crypt(cleartext)
            
    def test_arcfour(self):
        self._test(SHEX("01234567 89ABCDEF 00000000 00000000"),
                   SHEX("01234567 89ABCDEF"),
                   SHEX("69723659 1B5242B1"))
