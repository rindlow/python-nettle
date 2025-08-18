from unittest import TestCase

import nettle


def SDATA(string: str) -> bytes:
    return string.encode('ascii')


def SHEX(hexstring: str) -> bytes:
    return bytes.fromhex(hexstring)


class AES(TestCase):

    def _test(self, cipher: type[nettle.AesFamilyCipher], key: bytes,
              cleartext: bytes, ciphertext: bytes) -> None:
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
            c = cipher()
            c.set_encrypt_key(key[:-1])
        with self.assertRaises(nettle.KeyLenError):
            c = cipher()
            c.set_decrypt_key(key + b'a')
        with self.assertRaises(nettle.KeyLenError):
            c = cipher()
            c.set_encrypt_key(key[:-1])
        with self.assertRaises(nettle.KeyLenError):
            c = cipher()
            c.set_decrypt_key(key[:-1])
        with self.assertRaises(nettle.DataLenError):
            c = cipher()
            c.set_encrypt_key(key)
            c.encrypt(cleartext[:-1])
        with self.assertRaises(nettle.NotInitializedError):
            c = cipher()
            c.encrypt(cleartext)
        with self.assertRaises(nettle.NotInitializedError):
            c = cipher()
            c.decrypt(cleartext)

    def _test_invert(self, cipher: type[nettle.AesFamilyCipher],
                     key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher()
        c.set_encrypt_key(key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        c.invert_key()
        self.assertEqual(c.decrypt(ciphertext), cleartext)

    def _test_keywrap(self, cipher: type[nettle.AesFamilyCipher],
                      key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
        self.assertEqual(len(cleartext) + 8, len(ciphertext))
        c = cipher()
        c.set_encrypt_key(key)
        encrypted = c.keywrap(cleartext)
        self.assertEqual(encrypted, ciphertext)

        c.set_decrypt_key(key)
        decrypted = c.keyunwrap(ciphertext)
        self.assertEqual(decrypted, cleartext)

        with self.assertRaises(nettle.AuthenticationError):
            c.keyunwrap(bytes([0] * len(ciphertext)))


    def test_aes128(self) -> None:
        self._test(nettle.aes128,
                   SHEX("0001020305060708 0A0B0C0D0F101112"),
                   SHEX("506812A45F08C889 B97F5980038B8359"),
                   SHEX("D8F532538289EF7D 06B506A4FD5BE9C9"))

    def test_aes192(self) -> None:
        self._test(nettle.aes192,
                   SHEX("0001020305060708 0A0B0C0D0F101112"
                        "14151617191A1B1C"),
                   SHEX("2D33EEF2C0430A8A 9EBF45E809C40BB6"),
                   SHEX("DFF4945E0336DF4C 1C56BC700EFF837F"))

    def test_aes256(self) -> None:
        self._test(nettle.aes256,
                   SHEX("0001020305060708 0A0B0C0D0F101112"
                        "14151617191A1B1C 1E1F202123242526"),
                   SHEX("834EADFCCAC7E1B30664B1ABA44815AB"),
                   SHEX("1946DABF6A03A2A2 C3D0B05080AED6FC"))

    def test_aes128_invert(self) -> None:
        self._test_invert(nettle.aes128,
                          SHEX("0001020305060708 0A0B0C0D0F101112"),
                          SHEX("506812A45F08C889 B97F5980038B8359"),
                          SHEX("D8F532538289EF7D 06B506A4FD5BE9C9"))
        
    def test_aes128_keywrap(self) -> None:
        self._test_keywrap(nettle.aes128,
                    SHEX("0001020304050607 08090A0B0C0D0E0F"),
                    SHEX("0011223344556677 8899AABBCCDDEEFF"),
                    SHEX("1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"))

    def test_aes192_keywrap(self) -> None:
        self._test_keywrap(nettle.aes192,
                    SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617"),
                    SHEX("0011223344556677 8899AABBCCDDEEFF"),
                    SHEX("96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D"))

    def test_aes256_keywrap(self) -> None:
        self._test_keywrap(nettle.aes256,
                    SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                    SHEX("0011223344556677 8899AABBCCDDEEFF"),
                    SHEX("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7"))

class ARCFOUR(TestCase):

    def _test(self, key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
        self.assertEqual(len(cleartext), len(ciphertext))
        c = nettle.arcfour()
        with self.assertRaises(nettle.NotInitializedError):
            c.crypt(cleartext)
        self.assertEqual(len(key), c.key_size)
        c.set_key(key)
        self.assertEqual(c.crypt(cleartext), ciphertext)
        c.set_key(key)
        self.assertEqual(c.crypt(ciphertext), cleartext)
        c.set_key(key)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

        c = nettle.arcfour(key=key)
        self.assertEqual(c.crypt(cleartext), ciphertext)
        c = nettle.arcfour(key=key)
        self.assertEqual(c.crypt(ciphertext), cleartext)

        with self.assertRaises(nettle.NotInitializedError):
            c = nettle.arcfour()
            c.crypt(cleartext)

    def test_arcfour(self) -> None:
        self._test(SHEX("01234567 89ABCDEF 00000000 00000000"),
                   SHEX("01234567 89ABCDEF"),
                   SHEX("69723659 1B5242B1"))


class ARCTWO(TestCase):

    def _test(self, key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
        self.assertEqual(len(cleartext), len(ciphertext))
        c = nettle.arctwo()
        with self.assertRaises(nettle.NotInitializedError):
            c.encrypt(cleartext)
        c.set_key(key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

        c = nettle.arctwo(key=key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        c = nettle.arctwo(key=key)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

    def test_arctwo(self) -> None:
        self._test(SHEX("ffffffff ffffffff"),
                   SHEX("ffffffff ffffffff"),
                   SHEX("278b27e4 2e2f0d49"))


class Blowfish(TestCase):

    def _test(self, key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
        self.assertEqual(len(cleartext), len(ciphertext))
        c = nettle.blowfish()
        with self.assertRaises(nettle.NotInitializedError):
            c.encrypt(cleartext)
        c.set_key(key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

        c = nettle.blowfish(key=key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        c = nettle.blowfish(key=key)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

    def test_blowfish(self) -> None:
        self._test(SDATA("abcdefghijklmnopqrstuvwxyz"),
                   SDATA("BLOWFISH"),
                   SHEX("32 4E D0 FE F4 13 A2 03"))


class Camellia(TestCase):

    def _test(self, cipher: type[nettle.CamelliaFamilyCipher],
              key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher()
        with self.assertRaises(nettle.NotInitializedError):
            c.crypt(cleartext)
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

    def _test_invert(self, cipher: type[nettle.CamelliaFamilyCipher],
                     key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher(encrypt_key=key)
        self.assertEqual(c.crypt(cleartext), ciphertext)
        c.invert_key()
        self.assertEqual(c.crypt(ciphertext), cleartext)

    def test_camellia128(self) -> None:
        self._test(nettle.camellia128,
                   SHEX("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
                   SHEX("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
                   SHEX("67 67 31 38 54 96 69 73 08 57 06 56 48 ea be 43"))

    def test_camellia192(self) -> None:
        self._test(nettle.camellia192,
                   SHEX("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
                        "00 11 22 33 44 55 66 77"),
                   SHEX("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
                   SHEX("b4 99 34 01 b3 e9 96 f8 4e e5 ce e7 d7 9b 09 b9"))

    def test_camellia256(self) -> None:
        self._test(nettle.camellia256,
                   SHEX("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
                        "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"),
                   SHEX("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
                   SHEX("9a cc 23 7d ff 16 d7 6c 20 ef 7c 91 9e 3a 75 09"))

    def test_camellia128_invert(self) -> None:
        self._test_invert(nettle.camellia128,
                          SHEX("01 23 45 67 89 ab cd ef"
                               "fe dc ba 98 76 54 32 10"),
                          SHEX("01 23 45 67 89 ab cd ef"
                               "fe dc ba 98 76 54 32 10"),
                          SHEX("67 67 31 38 54 96 69 73"
                               "08 57 06 56 48 ea be 43"))


class CAST128(TestCase):

    def _test(self, key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
        self.assertEqual(len(cleartext), len(ciphertext))
        c = nettle.cast128()
        with self.assertRaises(nettle.NotInitializedError):
            c.encrypt(cleartext)
        c.set_key(key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

        c = nettle.cast128(key=key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        c = nettle.cast128(key=key)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

    def test_cast128(self) -> None:
        self._test(SHEX("01 23 45 67 12 34 56 78"
                        "23 45 67 89 34 56 78 9A"),
                   SHEX("01 23 45 67 89 AB CD EF"),
                   SHEX("23 8B 4F E5 84 7E 44 B2"))


class Salsa(TestCase):

    def _test(self, cipher: type[nettle.salsa20] | type[nettle.chacha],
              key: bytes, nonce: bytes, expected: bytes) -> None:
        self.assertEqual(len(key), 32)
        data = b'\0' * len(expected)
        c = cipher(key=key, nonce=nonce)
        self.assertEqual(c.crypt(data), expected)
        c = cipher(key=key, nonce=nonce)
        self.assertEqual(c.crypt(expected), data)

        c = cipher()
        with self.assertRaises(nettle.NotInitializedError):
            c.crypt(data)
        c.set_key(key)
        with self.assertRaises(nettle.NotInitializedError):
            c.crypt(data)
        c.set_nonce(nonce)
        self.assertEqual(c.crypt(data), expected)

    def test_salsa20(self) -> None:
        self._test(nettle.salsa20,
                   SHEX("80000000 00000000 00000000 00000000"
                        "00000000 00000000 00000000 00000000"),
                   SHEX("00000000 00000000"),
                   SHEX("E3BE8FDD 8BECA2E3"))

    def test_chacha(self) -> None:
        self._test(nettle.chacha,
                   SHEX("0000000000000000 0000000000000000"
                        "0000000000000000 0000000000000000"),
                   SHEX("0000000000000000"),
                   SHEX("76b8e0ada0f13d90 405d6ae55386bd28"
                        "bdd219b8a08ded1a a836efcc8b770dc7"
                        "da41597c5157488d 7724e03fb8d84a37"
                        "6a43b8f41518a11c c387b669b2ee6586"

                        "9f07e7be5551387a 98ba977c732d080d"
                        "cb0f29a048e36569 12c6533e32ee7aed"
                        "29b721769ce64e43 d57133b074d839d5"
                        "31ed1f28510afb45 ace10a1f4b794d6f"))


class DES(TestCase):

    def _test(self, cipher: type[nettle.DesFamilyCipher],
              key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher()
        self.assertTrue(c.check_parity(key))
        with self.assertRaises(nettle.NotInitializedError):
            c.encrypt(cleartext)
        c.set_key(key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

        c = cipher(key=key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        c = cipher(key=key)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

        key2 = bytearray(key)
        key2[-1] ^= 1
        self.assertFalse(c.check_parity(bytes(key2)))
        self.assertTrue(c.check_parity(c.fix_parity(bytes(key2))))

    def test_des(self) -> None:
        self._test(nettle.des,
                   SHEX("01234567 89ABCDEF"),
                   SHEX("01234567 89ABCDE7"),
                   SHEX("C9574425 6A5ED31D"))

    def test_des3(self) -> None:
        self._test(nettle.des3,
                   SHEX("3e 0b 10 b0 5d 49 c2 54"
                        "6b 46 e0 75 8a 91 61 85"
                        "cb 04 07 d3 20 16 cb a2"),
                   SDATA("Now is t"),
                   SHEX("0a 5d b5 2d 85 74 d1 c9"))


class Serpent(TestCase):

    def _test(self, cipher: type[nettle.SerpentFamilyCipher],
              key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher()
        # SERPENT_KEY_SIZE is only the default key size
        # self.assertEqual(len(key), c.key_size)
        with self.assertRaises(nettle.NotInitializedError):
            c.encrypt(cleartext)
        c.set_key(key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

        c = cipher(key=key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        c = cipher(key=key)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

    def test_serpent128(self) -> None:
        self._test(nettle.serpent,
                   SHEX("0000000000000000 0000000000000000"),
                   SHEX("D29D576FCEA3A3A7 ED9099F29273D78E"),
                   SHEX("B2288B968AE8B086 48D1CE9606FD992D"))

    def test_serpent192(self) -> None:
        self._test(nettle.serpent,
                   SHEX("0000000000000000 0000000000000000 0000000000000000"),
                   SHEX("D29D576FCEABA3A7 ED9899F2927BD78E"),
                   SHEX("130E353E1037C224 05E8FAEFB2C3C3E9"))

    def test_serpent256(self) -> None:
        self._test(nettle.serpent,
                   SHEX("0000000000000000 0000000000000000"
                        "0000000000000000 0000000000000000"),
                   SHEX("D095576FCEA3E3A7 ED98D9F29073D78E"),
                   SHEX("B90EE5862DE69168 F2BDD5125B45472B"))


class SM4(TestCase):

    def _test(self, cipher: type[nettle.Sm4FamilyCipher],
              key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher()
        with self.assertRaises(nettle.NotInitializedError):
            c.crypt(cleartext)
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

    def test_sm4(self) -> None:
        self._test(nettle.sm4,
                   SHEX("0123456789ABCDEF FEDCBA9876543210"),
                   SHEX("0123456789ABCDEF FEDCBA9876543210"),
                   SHEX("681EDF34D206965E 86B3E94F536E4246"))


class Twofish(TestCase):

    def _test(self, cipher: type[nettle.TwofishFamilyCipher],
              key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher()
        # TWOFISH_KEY_SIZE is only the default key size
        # self.assertEqual(len(key), c.key_size)
        with self.assertRaises(nettle.NotInitializedError):
            c.encrypt(cleartext)
        c.set_key(key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

        c = cipher(key=key)
        self.assertEqual(c.encrypt(cleartext), ciphertext)
        c = cipher(key=key)
        self.assertEqual(c.decrypt(ciphertext), cleartext)

        # with self.assertRaises(nettle.KeyLenError):
        #     c = cipher(key=key[:-1])

    def test_twofish128(self) -> None:
        self._test(nettle.twofish,
                   SHEX("0000000000000000 0000000000000000"),
                   SHEX("0000000000000000 0000000000000000"),
                   SHEX("9F589F5CF6122C32 B6BFEC2F2AE8C35A"))

    def test_twofish192(self) -> None:
        self._test(nettle.twofish,
                   SHEX("0123456789ABCDEF FEDCBA9876543210"
                        "0011223344556677"),
                   SHEX("0000000000000000 0000000000000000"),
                   SHEX("CFD1D2E5A9BE9CDF 501F13B892BD2248"))

    def test_twofish256(self) -> None:
        self._test(nettle.twofish,
                   SHEX("0123456789ABCDEF FEDCBA9876543210"
                        "0011223344556677 8899AABBCCDDEEFF"),
                   SHEX("0000000000000000 0000000000000000"),
                   SHEX("37527BE0052334B8 9F0CFCCAE87CFA20"))


class CTR(TestCase):

    def _test(self, cipher: type[nettle.AesFamilyCipher],
              key: bytes, cleartext: bytes, ciphertext: bytes, ctr: bytes):
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher(encrypt_key=key)
        self.assertGreater(c.block_size, 0)
        ctrmode = nettle.CTR(c, ctr)
        self.assertEqual(ctrmode.encrypt(cleartext), ciphertext)

        with self.assertRaises(nettle.KeyLenError):
            c = cipher(encrypt_key=key[:-1])
        with self.assertRaises(nettle.KeyLenError):
            c = cipher()
            c.set_encrypt_key(key[:-1])
        with self.assertRaises(nettle.KeyLenError):
            c = cipher()
            c.set_decrypt_key(key[:-1])

        with self.assertRaises(nettle.NotInitializedError):
            c = cipher()
            ctrmode = nettle.CTR(c, ctr)
            ctrmode.encrypt(cleartext)
        with self.assertRaises(nettle.NotInitializedError):
            c = cipher()
            ctrmode = nettle.CTR(c, ctr)
            ctrmode.encrypt(cleartext)

    def test_aes128_ctr(self):
        self._test(nettle.aes128,
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
        self._test(nettle.aes192,
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
        self._test(nettle.aes256,
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


class CBC(TestCase):

    def _test(self, cipher: type[nettle.AesFamilyCipher],
              key: bytes, cleartext: bytes, ciphertext: bytes, iv: bytes):
        self.assertEqual(len(cleartext), len(ciphertext))
        c = cipher(encrypt_key=key)
        cbc = nettle.CBC(c, iv)
        self.assertEqual(cbc.encrypt(cleartext), ciphertext)

        c = cipher(decrypt_key=key)
        cbc = nettle.CBC(c, iv)
        self.assertEqual(cbc.decrypt(ciphertext), cleartext)
        
        with self.assertRaises(nettle.KeyLenError):
            c = cipher(encrypt_key=key[:-1])
        with self.assertRaises(nettle.KeyLenError):
            c = cipher(decrypt_key=key + b'a')
        with self.assertRaises(nettle.KeyLenError):
            c = cipher()
            c.set_encrypt_key(key[:-1])
        with self.assertRaises(nettle.KeyLenError):
            c = cipher()
            c.set_decrypt_key(key[:-1])

        with self.assertRaises(nettle.NotInitializedError):
            c = cipher()
            cbc = nettle.CBC(c, iv)
            cbc.encrypt(cleartext)
        with self.assertRaises(nettle.NotInitializedError):
            c = cipher()
            cbc = nettle.CBC(c, iv)
            cbc.decrypt(cleartext)

    def test_aes128_cbc(self):
        self._test(nettle.aes128,
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
        self._test(nettle.aes192,
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
        self._test(nettle.aes256,
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


class GCM(TestCase):

    def _test(self, cipher: type[nettle.AesFamilyCipher],
              key: bytes, authtext: bytes, cleartext: bytes, ciphertext: bytes,
              iv: bytes, digest: bytes):
        self.assertEqual(len(cleartext), len(ciphertext))

        c = cipher(key)
        self.assertEqual(c.key_size, len(key))
        gcm = nettle.GCM(c, iv)
        gcm.update(authtext)
        self.assertEqual(gcm.encrypt(cleartext), ciphertext)
        self.assertEqual(gcm.digest(), digest)
        self.assertEqual(SHEX(gcm.hexdigest()), digest)
        self.assertEqual(gcm.digest(), digest)

        with self.assertRaises(nettle.KeyLenError):
            c = cipher(encrypt_key=key + b'a')
        with self.assertRaises(nettle.KeyLenError):
            c = cipher()
            c.set_encrypt_key(key[:-1])
        with self.assertRaises(nettle.KeyLenError):
            c = cipher()
            c.set_decrypt_key(key[:-1])

        with self.assertRaises(nettle.NotInitializedError):
            c = cipher()
            gcm = nettle.GCM(c, iv)
            gcm.encrypt(cleartext)
        with self.assertRaises(nettle.NotInitializedError):
            c = cipher()
            gcm = nettle.GCM(c, iv)
            gcm.decrypt(cleartext)

    def test_aes128_gcm(self):
        self._test(nettle.aes128,
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
        self._test(nettle.aes192,
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
        self._test(nettle.aes256,
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

    def test_camellia128_gcm(self):
        self._test(nettle.camellia128,
                   SHEX("00000000000000000000000000000000"),
                   SHEX(""),
                   SHEX(""),
                   SHEX(""),
                   SHEX("000000000000000000000000"),
                   SHEX("f5574acc3148dfcb9015200631024df9"))

    def test_camellia256_gcm(self):
        self._test(nettle.camellia256,
                   SHEX("feffe9928665731c 6d6a8f9467308308"
                        "feffe9928665731c 6d6a8f9467308308"),
                   SHEX("feedfacedeadbeef feedfacedeadbeef"
                        "abaddad2"),
                   SHEX("d9313225f88406e5 a55909c5aff5269a"
                        "86a7a9531534f7da 2e4c303d8a318a72"
                        "1c3c0c9595680953 2fcf0e2449a6b525"
                        "b16aedf5aa0de657 ba637b39"),
                   SHEX("ad142c11579dd95e 41f3c1f324dabc25"
                        "5864d920f1b65759 d8f560d4948d4477"
                        "58dfdcf77aa9f625 81c7ff572a037f81"
                        "0cb1a9c4b3ca6ed6 38179b77"),
                   SHEX("cafebabefacedbaddecaf888"),
                   SHEX("4e4b178d8fe26fdc95e2e7246dd94bec"))


class EAX(TestCase):

    def _test(self, cipher: type[nettle.AesFamilyCipher],
              key: bytes, authtext: bytes, cleartext: bytes, ciphertext: bytes,
              nonce: bytes, digest: bytes):
        self.assertEqual(len(cleartext), len(ciphertext))

        c = cipher(key)
        self.assertEqual(c.key_size, len(key))
        eax = nettle.EAX(c, nonce)
        eax.update(authtext)

        self.assertEqual(eax.encrypt(cleartext), ciphertext)
        self.assertEqual(eax.digest(), digest)
        self.assertEqual(SHEX(eax.hexdigest()), digest)
        self.assertEqual(eax.digest(), digest)

        with self.assertRaises(nettle.KeyLenError):
            c = cipher(encrypt_key=key + b'a')
        with self.assertRaises(nettle.KeyLenError):
            c = cipher()
            c.set_encrypt_key(key[:-1])
        with self.assertRaises(nettle.KeyLenError):
            c = cipher()
            c.set_decrypt_key(key[:-1])

        with self.assertRaises(nettle.NotInitializedError):
            c = cipher()
            eax = nettle.EAX(c, nonce)
            eax.encrypt(cleartext)
        with self.assertRaises(nettle.NotInitializedError):
            c = cipher()
            eax = nettle.EAX(c, nonce)
            eax.decrypt(cleartext)

    def test_aes128_eax(self):
        self._test(nettle.aes128,
                   SHEX("01F74AD64077F2E704C0F60ADA3DD523"),
                   SHEX("234A3463C1264AC6"),
                   SHEX("1A47CB4933"),
                   SHEX("D851D5BAE0"),
                   SHEX("70C3DB4F0D26368400A10ED05D2BFF5E"),
                   SHEX("3A59F238A23E39199DC9266626C40F80"))
        self._test(nettle.aes128,
                   SHEX("233952DEE4D5ED5F9B9C6D6FF80FF478"),
                   SHEX("6BFB914FD07EAE6B"),
                   SHEX(""),
                   SHEX(""),
                   SHEX("62EC67F9C3A4A407FCB2A8C49031A8B3"),
                   SHEX("E037830E8389F27B025A2D6527E79D01"))


class CCM(TestCase):

    def _test(self, cipher: type[nettle.AesFamilyCipher],
              key: bytes, nonce: bytes, authtext: bytes,
              cleartext: bytes, cipherdigest: bytes):
        clen = len(cleartext)
        ciphertext = cipherdigest[:clen]
        digest = cipherdigest[clen:]
        self.assertEqual(len(cleartext), len(ciphertext))

        c = cipher(key)
        self.assertEqual(c.key_size, len(key))
        ccm = nettle.CCM(c, nonce, len(authtext), len(cleartext), len(digest))
        ccm.update(authtext)

        self.assertEqual(ccm.encrypt(cleartext), ciphertext)
        self.assertEqual(ccm.digest(), digest)
        self.assertEqual(SHEX(ccm.hexdigest()), digest)
        self.assertEqual(ccm.digest(), digest)

        with self.assertRaises(nettle.KeyLenError):
            c = cipher(encrypt_key=key + b'a')
        with self.assertRaises(nettle.KeyLenError):
            c = cipher()
            c.set_encrypt_key(key[:-1])
        with self.assertRaises(nettle.KeyLenError):
            c = cipher()
            c.set_decrypt_key(key[:-1])

        with self.assertRaises(nettle.NotInitializedError):
            c = cipher()
            ccm = nettle.CCM(c, nonce, len(authtext), len(cleartext),
                             len(digest))
            ccm.encrypt(cleartext)
        with self.assertRaises(nettle.NotInitializedError):
            c = cipher()
            ccm = nettle.CCM(c, nonce, len(authtext), len(cleartext),
                             len(digest))
            ccm.decrypt(cleartext)

        with self.assertRaises(nettle.LenMismatch):
            c = cipher(key)
            ccm = nettle.CCM(c, nonce, len(authtext), len(cleartext) - 1,
                             len(digest))
            ccm.update(authtext)
            ccm.encrypt(cleartext)

        with self.assertRaises(nettle.LenMismatch):
            c = cipher(key)
            ccm = nettle.CCM(c, nonce, len(authtext) - 1, len(cleartext),
                             len(digest))
            ccm.update(authtext)
            ccm.encrypt(cleartext)

    def test_aes128_ccm(self):
        self._test(nettle.aes128,
                   SHEX("404142434445464748494a4b4c4d4e4f"),
                   SHEX("10111213141516"),
                   SHEX("0001020304050607"),
                   SHEX("20212223"),
                   SHEX("7162015b 4dac255d"))
        self._test(nettle.aes256,
                   SHEX("000000000000000000000000"
                        "000000000000000000000000"
                        "0000000000000000"),
                   SHEX("000000000000000000000000"),
                   SHEX(""),
                   SHEX("00000000000000000000000000000000"),
                   SHEX("c1944044c8e7aa95d2de9513c7f3dd8c"
                        "4b0a3e5e51f151eb0ffae7c43d010fdb"))
