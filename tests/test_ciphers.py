import nettle
import pytest


def sdata(string: str) -> bytes:
    return string.encode("ascii")


def shex(hexstring: str) -> bytes:
    return bytes.fromhex(hexstring)


@pytest.mark.parametrize(
    ("cipher", "key", "cleartext", "ciphertext"),
    [
        (
            nettle.AES128,
            shex("0001020305060708 0A0B0C0D0F101112"),
            shex("506812A45F08C889 B97F5980038B8359"),
            shex("D8F532538289EF7D 06B506A4FD5BE9C9"),
        ),
        (
            nettle.AES192,
            shex("0001020305060708 0A0B0C0D0F10111214151617191A1B1C"),
            shex("2D33EEF2C0430A8A 9EBF45E809C40BB6"),
            shex("DFF4945E0336DF4C 1C56BC700EFF837F"),
        ),
        (
            nettle.AES256,
            shex("0001020305060708 0A0B0C0D0F10111214151617191A1B1C 1E1F202123242526"),
            shex("834EADFCCAC7E1B30664B1ABA44815AB"),
            shex("1946DABF6A03A2A2 C3D0B05080AED6FC"),
        ),
    ],
)
def test_cipher(
    cipher: type[nettle.Cipher],
    key: bytes,
    cleartext: bytes,
    ciphertext: bytes,
) -> None:
    assert len(cleartext) == len(ciphertext)
    c = cipher()
    assert len(key) == c.key_size
    c.set_encrypt_key(key)
    assert c.encrypt(cleartext) == ciphertext
    c.set_decrypt_key(key)
    assert c.decrypt(ciphertext) == cleartext

    c = cipher(encrypt_key=key)
    assert c.encrypt(cleartext) == ciphertext
    c = cipher(decrypt_key=key)
    assert c.decrypt(ciphertext) == cleartext

    c = cipher()
    with pytest.raises(nettle.KeyLenError):
        c.set_encrypt_key(key[:-1])
    with pytest.raises(nettle.KeyLenError):
        c.set_decrypt_key(key + b"a")
    with pytest.raises(nettle.KeyLenError):
        c.set_encrypt_key(key[:-1])
    with pytest.raises(nettle.KeyLenError):
        c.set_decrypt_key(key[:-1])
    c.set_encrypt_key(key)
    with pytest.raises(nettle.DataLenError):
        c.encrypt(cleartext[:-1])
    c = cipher()
    with pytest.raises(nettle.NotInitializedError):
        c.encrypt(cleartext)
    c = cipher()
    with pytest.raises(nettle.NotInitializedError):
        c.decrypt(cleartext)


@pytest.mark.parametrize(
    ("cipher", "key", "cleartext", "ciphertext"),
    [
        (
            nettle.AES128,
            shex("0001020305060708 0A0B0C0D0F101112"),
            shex("506812A45F08C889 B97F5980038B8359"),
            shex("D8F532538289EF7D 06B506A4FD5BE9C9"),
        )
    ],
)
def test_invert(
    cipher: type[nettle.InvertibleKeyCipher],
    key: bytes,
    cleartext: bytes,
    ciphertext: bytes,
) -> None:
    assert len(cleartext) == len(ciphertext)
    c = cipher()
    c.set_encrypt_key(key)
    assert c.encrypt(cleartext) == ciphertext
    c.invert_key()
    assert c.decrypt(ciphertext) == cleartext


@pytest.mark.parametrize(
    ("cipher", "key", "cleartext", "ciphertext"),
    [
        (
            nettle.AES128,
            shex("0001020304050607 08090A0B0C0D0E0F"),
            shex("0011223344556677 8899AABBCCDDEEFF"),
            shex("1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"),
        ),
        (
            nettle.AES192,
            shex("0001020304050607 08090A0B0C0D0E0F 1011121314151617"),
            shex("0011223344556677 8899AABBCCDDEEFF"),
            shex("96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D"),
        ),
        (
            nettle.AES256,
            shex("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
            shex("0011223344556677 8899AABBCCDDEEFF"),
            shex("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7"),
        ),
    ],
)
def test_keywrap(
    cipher: type[nettle.KeyWrapCipher],
    key: bytes,
    cleartext: bytes,
    ciphertext: bytes,
) -> None:
    assert len(cleartext) + 8 == len(ciphertext)
    c = cipher()
    c.set_encrypt_key(key)
    encrypted = c.keywrap(cleartext)
    assert encrypted == ciphertext

    c.set_decrypt_key(key)
    decrypted = c.keyunwrap(ciphertext)
    assert decrypted == cleartext

    with pytest.raises(nettle.AuthenticationError):
        c.keyunwrap(bytes([0] * len(ciphertext)))


# class ARCFOUR(TestCase):
#
#     def _test(self, key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
#         self.assertEqual(len(cleartext), len(ciphertext))
#         c = nettle.Arcfour()
#         with pytest.raises(nettle.NotInitializedError):
#             c.crypt(cleartext)
#         self.assertEqual(len(key), c.key_size)
#         c.set_key(key)
#         self.assertEqual(c.crypt(cleartext), ciphertext)
#         c.set_key(key)
#         self.assertEqual(c.crypt(ciphertext), cleartext)
#         c.set_key(key)
#         self.assertEqual(c.decrypt(ciphertext), cleartext)
#
#         c = nettle.Arcfour(key=key)
#         self.assertEqual(c.crypt(cleartext), ciphertext)
#         c = nettle.Arcfour(key=key)
#         self.assertEqual(c.crypt(ciphertext), cleartext)
#
#         with pytest.raises(nettle.NotInitializedError):
#             c = nettle.Arcfour()
#             c.crypt(cleartext)
#
#     def test_arcfour() -> None:
#         _test(shex("01234567 89ABCDEF 00000000 00000000"),
#                    shex("01234567 89ABCDEF"),
#                    shex("69723659 1B5242B1"))
#
#
# class ARCTWO(TestCase):
#
#     def _test(self, key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
#         self.assertEqual(len(cleartext), len(ciphertext))
#         c = nettle.Arctwo()
#         with pytest.raises(nettle.NotInitializedError):
#             c.encrypt(cleartext)
#         c.set_key(key)
#         self.assertEqual(c.encrypt(cleartext), ciphertext)
#         self.assertEqual(c.decrypt(ciphertext), cleartext)
#
#         c = nettle.Arctwo(key=key)
#         self.assertEqual(c.encrypt(cleartext), ciphertext)
#         c = nettle.Arctwo(key=key)
#         self.assertEqual(c.decrypt(ciphertext), cleartext)
#
#     def test_arctwo() -> None:
#         _test(shex("ffffffff ffffffff"),
#                    shex("ffffffff ffffffff"),
#                    shex("278b27e4 2e2f0d49"))
#
#
# class Blowfish(TestCase):
#
#     def _test(self, key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
#         self.assertEqual(len(cleartext), len(ciphertext))
#         c = nettle.Blowfish()
#         with pytest.raises(nettle.NotInitializedError):
#             c.encrypt(cleartext)
#         c.set_key(key)
#         self.assertEqual(c.encrypt(cleartext), ciphertext)
#         self.assertEqual(c.decrypt(ciphertext), cleartext)
#
#         c = nettle.Blowfish(key=key)
#         self.assertEqual(c.encrypt(cleartext), ciphertext)
#         c = nettle.Blowfish(key=key)
#         self.assertEqual(c.decrypt(ciphertext), cleartext)
#
#     def test_blowfish() -> None:
#         _test(sdata("abcdefghijklmnopqrstuvwxyz"),
#                    sdata("BLOWFISH"),
#                    shex("32 4E D0 FE F4 13 A2 03"))
#
#
# class Camellia(TestCase):
#
#     def _test(self, cipher: type[nettle.CamelliaFamilyCipher],
#               key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
#         self.assertEqual(len(cleartext), len(ciphertext))
#         c = cipher()
#         with pytest.raises(nettle.NotInitializedError):
#             c.crypt(cleartext)
#         self.assertEqual(len(key), c.key_size)
#         c.set_encrypt_key(key)
#         self.assertEqual(c.crypt(cleartext), ciphertext)
#         c.set_decrypt_key(key)
#         self.assertEqual(c.crypt(ciphertext), cleartext)
#
#         c = cipher(encrypt_key=key)
#         self.assertEqual(c.crypt(cleartext), ciphertext)
#         c = cipher(decrypt_key=key)
#         self.assertEqual(c.crypt(ciphertext), cleartext)
#
#         with pytest.raises(nettle.KeyLenError):
#             c = cipher(encrypt_key=key[:-1])
#
#     def _test_invert(self, cipher: type[nettle.CamelliaFamilyCipher],
#                      key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
#         self.assertEqual(len(cleartext), len(ciphertext))
#         c = cipher(encrypt_key=key)
#         self.assertEqual(c.crypt(cleartext), ciphertext)
#         c.invert_key()
#         self.assertEqual(c.crypt(ciphertext), cleartext)
#
#     def test_camellia128() -> None:
#         _test(nettle.Camellia128,
#                    shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
#                    shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
#                    shex("67 67 31 38 54 96 69 73 08 57 06 56 48 ea be 43"))
#
#     def test_camellia192() -> None:
#         _test(nettle.Camellia192,
#                    shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
#                         "00 11 22 33 44 55 66 77"),
#                    shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
#                    shex("b4 99 34 01 b3 e9 96 f8 4e e5 ce e7 d7 9b 09 b9"))
#
#     def test_camellia256() -> None:
#         _test(nettle.Camellia256,
#                    shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
#                         "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"),
#                    shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
#                    shex("9a cc 23 7d ff 16 d7 6c 20 ef 7c 91 9e 3a 75 09"))
#
#     def test_camellia128_invert() -> None:
#         _test_invert(nettle.Camellia128,
#                           shex("01 23 45 67 89 ab cd ef"
#                                "fe dc ba 98 76 54 32 10"),
#                           shex("01 23 45 67 89 ab cd ef"
#                                "fe dc ba 98 76 54 32 10"),
#                           shex("67 67 31 38 54 96 69 73"
#                                "08 57 06 56 48 ea be 43"))
#
#
# class CAST128(TestCase):
#
#     def _test(self, key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
#         self.assertEqual(len(cleartext), len(ciphertext))
#         c = nettle.CAST128()
#         with pytest.raises(nettle.NotInitializedError):
#             c.encrypt(cleartext)
#         c.set_key(key)
#         self.assertEqual(c.encrypt(cleartext), ciphertext)
#         self.assertEqual(c.decrypt(ciphertext), cleartext)
#
#         c = nettle.CAST128(key=key)
#         self.assertEqual(c.encrypt(cleartext), ciphertext)
#         c = nettle.CAST128(key=key)
#         self.assertEqual(c.decrypt(ciphertext), cleartext)
#
#     def test_cast128() -> None:
#         _test(shex("01 23 45 67 12 34 56 78"
#                         "23 45 67 89 34 56 78 9A"),
#                    shex("01 23 45 67 89 AB CD EF"),
#                    shex("23 8B 4F E5 84 7E 44 B2"))
#
#
# class Salsa(TestCase):
#
#     def _test(self, cipher: type[nettle.Salsa20] | type[nettle.ChaCha],
#               key: bytes, nonce: bytes, expected: bytes) -> None:
#         self.assertEqual(len(key), 32)
#         data = b'\0' * len(expected)
#         c = cipher(key=key, nonce=nonce)
#         self.assertEqual(c.crypt(data), expected)
#         c = cipher(key=key, nonce=nonce)
#         self.assertEqual(c.crypt(expected), data)
#
#         c = cipher()
#         with pytest.raises(nettle.NotInitializedError):
#             c.crypt(data)
#         c.set_key(key)
#         with pytest.raises(nettle.NotInitializedError):
#             c.crypt(data)
#         c.set_nonce(nonce)
#         self.assertEqual(c.crypt(data), expected)
#
#     def test_salsa20() -> None:
#         _test(nettle.Salsa20,
#                    shex("80000000 00000000 00000000 00000000"
#                         "00000000 00000000 00000000 00000000"),
#                    shex("00000000 00000000"),
#                    shex("E3BE8FDD 8BECA2E3"))
#
#     def test_chacha() -> None:
#         _test(nettle.ChaCha,
#                    shex("0000000000000000 0000000000000000"
#                         "0000000000000000 0000000000000000"),
#                    shex("0000000000000000"),
#                    shex("76b8e0ada0f13d90 405d6ae55386bd28"
#                         "bdd219b8a08ded1a a836efcc8b770dc7"
#                         "da41597c5157488d 7724e03fb8d84a37"
#                         "6a43b8f41518a11c c387b669b2ee6586"
#
#                         "9f07e7be5551387a 98ba977c732d080d"
#                         "cb0f29a048e36569 12c6533e32ee7aed"
#                         "29b721769ce64e43 d57133b074d839d5"
#                         "31ed1f28510afb45 ace10a1f4b794d6f"))
#
#
# class DES(TestCase):
#
#     def _test(self, cipher: type[nettle.DesFamilyCipher],
#               key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
#         self.assertEqual(len(cleartext), len(ciphertext))
#         c = cipher()
#         self.assertTrue(c.check_parity(key))
#         with pytest.raises(nettle.NotInitializedError):
#             c.encrypt(cleartext)
#         c.set_key(key)
#         self.assertEqual(c.encrypt(cleartext), ciphertext)
#         self.assertEqual(c.decrypt(ciphertext), cleartext)
#
#         c = cipher(key=key)
#         self.assertEqual(c.encrypt(cleartext), ciphertext)
#         c = cipher(key=key)
#         self.assertEqual(c.decrypt(ciphertext), cleartext)
#
#         key2 = bytearray(key)
#         key2[-1] ^= 1
#         self.assertFalse(c.check_parity(bytes(key2)))
#         self.assertTrue(c.check_parity(c.fix_parity(bytes(key2))))
#
#     def test_des() -> None:
#         _test(nettle.DES,
#                    shex("01234567 89ABCDEF"),
#                    shex("01234567 89ABCDE7"),
#                    shex("C9574425 6A5ED31D"))
#
#     def test_des3() -> None:
#         _test(nettle.DES3,
#                    shex("3e 0b 10 b0 5d 49 c2 54"
#                         "6b 46 e0 75 8a 91 61 85"
#                         "cb 04 07 d3 20 16 cb a2"),
#                    sdata("Now is t"),
#                    shex("0a 5d b5 2d 85 74 d1 c9"))
#
#
# class Serpent(TestCase):
#
#     def _test(self, cipher: type[nettle.SerpentFamilyCipher],
#               key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
#         self.assertEqual(len(cleartext), len(ciphertext))
#         c = cipher()
#         # SERPENT_KEY_SIZE is only the default key size
#         # self.assertEqual(len(key), c.key_size)
#         with pytest.raises(nettle.NotInitializedError):
#             c.encrypt(cleartext)
#         c.set_key(key)
#         self.assertEqual(c.encrypt(cleartext), ciphertext)
#         self.assertEqual(c.decrypt(ciphertext), cleartext)
#
#         c = cipher(key=key)
#         self.assertEqual(c.encrypt(cleartext), ciphertext)
#         c = cipher(key=key)
#         self.assertEqual(c.decrypt(ciphertext), cleartext)
#
#     def test_serpent128() -> None:
#         _test(nettle.Serpent,
#                    shex("0000000000000000 0000000000000000"),
#                    shex("D29D576FCEA3A3A7 ED9099F29273D78E"),
#                    shex("B2288B968AE8B086 48D1CE9606FD992D"))
#
#     def test_serpent192() -> None:
#         _test(nettle.Serpent,
#                    shex("0000000000000000 0000000000000000 0000000000000000"),
#                    shex("D29D576FCEABA3A7 ED9899F2927BD78E"),
#                    shex("130E353E1037C224 05E8FAEFB2C3C3E9"))
#
#     def test_serpent256() -> None:
#         _test(nettle.Serpent,
#                    shex("0000000000000000 0000000000000000"
#                         "0000000000000000 0000000000000000"),
#                    shex("D095576FCEA3E3A7 ED98D9F29073D78E"),
#                    shex("B90EE5862DE69168 F2BDD5125B45472B"))
#
#
# class SM4(TestCase):
#
#     def _test(self, cipher: type[nettle.Sm4FamilyCipher],
#               key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
#         self.assertEqual(len(cleartext), len(ciphertext))
#         c = cipher()
#         with pytest.raises(nettle.NotInitializedError):
#             c.crypt(cleartext)
#         self.assertEqual(len(key), c.key_size)
#         c.set_encrypt_key(key)
#         self.assertEqual(c.crypt(cleartext), ciphertext)
#         c.set_decrypt_key(key)
#         self.assertEqual(c.crypt(ciphertext), cleartext)
#
#         c = cipher(encrypt_key=key)
#         self.assertEqual(c.crypt(cleartext), ciphertext)
#         c = cipher(decrypt_key=key)
#         self.assertEqual(c.crypt(ciphertext), cleartext)
#
#         with pytest.raises(nettle.KeyLenError):
#             c = cipher(encrypt_key=key[:-1])
#
#     def test_sm4() -> None:
#         _test(nettle.SM4,
#                    shex("0123456789ABCDEF FEDCBA9876543210"),
#                    shex("0123456789ABCDEF FEDCBA9876543210"),
#                    shex("681EDF34D206965E 86B3E94F536E4246"))
#
#
# class Twofish(TestCase):
#
#     def _test(self, cipher: type[nettle.TwofishFamilyCipher],
#               key: bytes, cleartext: bytes, ciphertext: bytes) -> None:
#         self.assertEqual(len(cleartext), len(ciphertext))
#         c = cipher()
#         # TWOFISH_KEY_SIZE is only the default key size
#         # self.assertEqual(len(key), c.key_size)
#         with pytest.raises(nettle.NotInitializedError):
#             c.encrypt(cleartext)
#         c.set_key(key)
#         self.assertEqual(c.encrypt(cleartext), ciphertext)
#         self.assertEqual(c.decrypt(ciphertext), cleartext)
#
#         c = cipher(key=key)
#         self.assertEqual(c.encrypt(cleartext), ciphertext)
#         c = cipher(key=key)
#         self.assertEqual(c.decrypt(ciphertext), cleartext)
#
#         # with pytest.raises(nettle.KeyLenError):
#         #     c = cipher(key=key[:-1])
#
#     def test_twofish128() -> None:
#         _test(nettle.Twofish,
#                    shex("0000000000000000 0000000000000000"),
#                    shex("0000000000000000 0000000000000000"),
#                    shex("9F589F5CF6122C32 B6BFEC2F2AE8C35A"))
#
#     def test_twofish192() -> None:
#         _test(nettle.Twofish,
#                    shex("0123456789ABCDEF FEDCBA9876543210"
#                         "0011223344556677"),
#                    shex("0000000000000000 0000000000000000"),
#                    shex("CFD1D2E5A9BE9CDF 501F13B892BD2248"))
#
#     def test_twofish256() -> None:
#         _test(nettle.Twofish,
#                    shex("0123456789ABCDEF FEDCBA9876543210"
#                         "0011223344556677 8899AABBCCDDEEFF"),
#                    shex("0000000000000000 0000000000000000"),
#                    shex("37527BE0052334B8 9F0CFCCAE87CFA20"))
#
#
# class CTR(TestCase):
#
#     def _test(self, cipher: type[nettle.AesFamilyCipher],
#               key: bytes, cleartext: bytes, ciphertext: bytes, ctr: bytes):
#         self.assertEqual(len(cleartext), len(ciphertext))
#         c = cipher(encrypt_key=key)
#         self.assertGreater(c.block_size, 0)
#         ctrmode = nettle.CTR(c, ctr)
#         self.assertEqual(ctrmode.encrypt(cleartext), ciphertext)
#
#         with pytest.raises(nettle.KeyLenError):
#             c = cipher(encrypt_key=key[:-1])
#         with pytest.raises(nettle.KeyLenError):
#             c = cipher()
#             c.set_encrypt_key(key[:-1])
#         with pytest.raises(nettle.KeyLenError):
#             c = cipher()
#             c.set_decrypt_key(key[:-1])
#
#         with pytest.raises(nettle.NotInitializedError):
#             c = cipher()
#             ctrmode = nettle.CTR(c, ctr)
#             ctrmode.encrypt(cleartext)
#         with pytest.raises(nettle.NotInitializedError):
#             c = cipher()
#             ctrmode = nettle.CTR(c, ctr)
#             ctrmode.encrypt(cleartext)
#
#     def test_aes128_ctr():
#         _test(nettle.AES128,
#                    shex("2b7e151628aed2a6abf7158809cf4f3c"),
#                    shex("6bc1bee22e409f96e93d7e117393172a"
#                         "ae2d8a571e03ac9c9eb76fac45af8e51"
#                         "30c81c46a35ce411e5fbc1191a0a52ef"
#                         "f69f2445df4f9b17ad2b417be66c3710"),
#                    shex("874d6191b620e3261bef6864990db6ce"
#                         "9806f66b7970fdff8617187bb9fffdff"
#                         "5ae4df3edbd5d35e5b4f09020db03eab"
#                         "1e031dda2fbe03d1792170a0f3009cee"),
#                    shex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
#
#     def test_aes192_ctr():
#         _test(nettle.AES192,
#                    shex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
#                    shex("6bc1bee22e409f96e93d7e117393172a"
#                         "ae2d8a571e03ac9c9eb76fac45af8e51"
#                         "30c81c46a35ce411e5fbc1191a0a52ef"
#                         "f69f2445df4f9b17ad2b417be66c3710"),
#                    shex("1abc932417521ca24f2b0459fe7e6e0b"
#                         "090339ec0aa6faefd5ccc2c6f4ce8e94"
#                         "1e36b26bd1ebc670d1bd1d665620abf7"
#                         "4f78a7f6d29809585a97daec58c6b050"),
#                    shex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
#
#     def test_aes256_ctr():
#         _test(nettle.AES256,
#                    shex("603deb1015ca71be2b73aef0857d7781"
#                         "1f352c073b6108d72d9810a30914dff4"),
#                    shex("6bc1bee22e409f96e93d7e117393172a"
#                         "ae2d8a571e03ac9c9eb76fac45af8e51"
#                         "30c81c46a35ce411e5fbc1191a0a52ef"
#                         "f69f2445df4f9b17ad2b417be66c3710"),
#                    shex("601ec313775789a5b7a7f504bbf3d228"
#                         "f443e3ca4d62b59aca84e990cacaf5c5"
#                         "2b0930daa23de94ce87017ba2d84988d"
#                         "dfc9c58db67aada613c2dd08457941a6"),
#                    shex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
#
#


@pytest.mark.parametrize(
    ("cipher", "key", "cleartext", "ciphertext", "iv"),
    [
        (
            nettle.AES128,
            shex("2b7e151628aed2a6abf7158809cf4f3c"),
            shex(
                "6bc1bee22e409f96e93d7e117393172a"
                "ae2d8a571e03ac9c9eb76fac45af8e51"
                "30c81c46a35ce411e5fbc1191a0a52ef"
                "f69f2445df4f9b17ad2b417be66c3710"
            ),
            shex(
                "7649abac8119b246cee98e9b12e9197d"
                "5086cb9b507219ee95db113a917678b2"
                "73bed6b8e3c1743b7116e69e22229516"
                "3ff1caa1681fac09120eca307586e1a7"
            ),
            shex("000102030405060708090a0b0c0d0e0f"),
        ),
        (
            nettle.AES192,
            shex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
            shex(
                "6bc1bee22e409f96e93d7e117393172a"
                "ae2d8a571e03ac9c9eb76fac45af8e51"
                "30c81c46a35ce411e5fbc1191a0a52ef"
                "f69f2445df4f9b17ad2b417be66c3710"
            ),
            shex(
                "4f021db243bc633d7178183a9fa071e8"
                "b4d9ada9ad7dedf4e5e738763f69145a"
                "571b242012fb7ae07fa9baac3df102e0"
                "08b0e27988598881d920a9e64f5615cd"
            ),
            shex("000102030405060708090a0b0c0d0e0f"),
        ),
        (
            nettle.AES256,
            shex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            shex(
                "6bc1bee22e409f96e93d7e117393172a"
                "ae2d8a571e03ac9c9eb76fac45af8e51"
                "30c81c46a35ce411e5fbc1191a0a52ef"
                "f69f2445df4f9b17ad2b417be66c3710"
            ),
            shex(
                "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                "9cfc4e967edb808d679f777bc6702c7d"
                "39f23369a9d9bacfa530e26304231461"
                "b2eb05e2c39be9fcda6c19078c6a9d1b"
            ),
            shex("000102030405060708090a0b0c0d0e0f"),
        ),
    ],
)
def test_cbc(
    cipher: type[nettle.BlockCipher],
    key: bytes,
    cleartext: bytes,
    ciphertext: bytes,
    iv: bytes,
) -> None:

    assert len(cleartext) == len(ciphertext)

    c = cipher(encrypt_key=key)
    cbc = nettle.CBC(c, iv)
    assert cbc.encrypt(cleartext) == ciphertext

    c = cipher()
    c.set_decrypt_key(key)
    cbc = nettle.CBC(c, iv)
    assert cbc.decrypt(ciphertext) == cleartext

    c = cipher()
    cbc = nettle.CBC(c, iv)
    with pytest.raises(nettle.NotInitializedError):
        cbc.encrypt(cleartext)
    with pytest.raises(nettle.NotInitializedError):
        cbc.decrypt(cleartext)


@pytest.mark.parametrize(
    ("cipher", "mode", "key", "authtext", "cleartext", "ciphertext", "iv", "digest"),
    [
        (
            nettle.AES128,
            nettle.GCM,
            shex("feffe9928665731c6d6a8f9467308308"),
            shex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
            shex(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39"
            ),
            shex(
                "42831ec2217774244b7221b784d0d49c"
                "e3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa05"
                "1ba30b396a0aac973d58e091"
            ),
            shex("cafebabefacedbaddecaf888"),
            shex("5bc94fbc3221a5db94fae95ae7121a47"),
        )
    ],
)
def test_aead(
    cipher: type[nettle.BlockCipher],
    mode: type[nettle.AEADCipherMode],
    key: bytes,
    authtext: bytes,
    cleartext: bytes,
    ciphertext: bytes,
    iv: bytes,
    digest: bytes,
):
    assert len(cleartext) == len(ciphertext)

    c = cipher(encrypt_key=key)
    assert c.key_size == len(key)
    aead = mode(c, iv)
    aead.update(authtext)
    assert aead.encrypt(cleartext) == ciphertext
    assert aead.digest() == digest

    c = cipher(encrypt_key=key)
    aead = mode(c, iv)
    aead.update(authtext)
    aead.encrypt(cleartext)
    assert shex(aead.hexdigest()) == digest

    c = cipher(encrypt_key=key)
    aead = mode(c, iv)
    aead.update(authtext)
    assert aead.decrypt(ciphertext) == cleartext

    c = cipher()
    with pytest.raises(nettle.NotInitializedError):
        aead = mode(c, iv)


#
#     def test_aes192_gcm():
#         _test(nettle.AES192,
#                    shex("feffe9928665731c6d6a8f9467308308"
#                         "feffe9928665731c"),
#                    shex("feedfacedeadbeeffeedfacedeadbeef"
#                         "abaddad2"),
#                    shex("d9313225f88406e5a55909c5aff5269a"
#                         "86a7a9531534f7da2e4c303d8a318a72"
#                         "1c3c0c95956809532fcf0e2449a6b525"
#                         "b16aedf5aa0de657ba637b39"),
#                    shex("3980ca0b3c00e841eb06fac4872a2757"
#                         "859e1ceaa6efd984628593b40ca1e19c"
#                         "7d773d00c144c525ac619d18c84a3f47"
#                         "18e2448b2fe324d9ccda2710"),
#                    shex("cafebabefacedbaddecaf888"),
#                    shex("2519498e80f1478f37ba55bd6d27618c"))
#
#     def test_aes256_gcm():
#         _test(nettle.AES256,
#                    shex("feffe9928665731c6d6a8f9467308308"
#                         "feffe9928665731c6d6a8f9467308308"),
#                    shex("feedfacedeadbeeffeedfacedeadbeef"
#                         "abaddad2"),
#                    shex("d9313225f88406e5a55909c5aff5269a"
#                         "86a7a9531534f7da2e4c303d8a318a72"
#                         "1c3c0c95956809532fcf0e2449a6b525"
#                         "b16aedf5aa0de657ba637b39"),
#                    shex("522dc1f099567d07f47f37a32a84427d"
#                         "643a8cdcbfe5c0c97598a2bd2555d1aa"
#                         "8cb08e48590dbb3da7b08b1056828838"
#                         "c5f61e6393ba7a0abcc9f662"),
#                    shex("cafebabefacedbaddecaf888"),
#                    shex("76fc6ece0f4e1768cddf8853bb2d551b"))
#
#     def test_camellia128_gcm():
#         _test(nettle.Camellia128,
#                    shex("00000000000000000000000000000000"),
#                    shex(""),
#                    shex(""),
#                    shex(""),
#                    shex("000000000000000000000000"),
#                    shex("f5574acc3148dfcb9015200631024df9"))
#
#     def test_camellia256_gcm():
#         _test(nettle.Camellia256,
#                    shex("feffe9928665731c 6d6a8f9467308308"
#                         "feffe9928665731c 6d6a8f9467308308"),
#                    shex("feedfacedeadbeef feedfacedeadbeef"
#                         "abaddad2"),
#                    shex("d9313225f88406e5 a55909c5aff5269a"
#                         "86a7a9531534f7da 2e4c303d8a318a72"
#                         "1c3c0c9595680953 2fcf0e2449a6b525"
#                         "b16aedf5aa0de657 ba637b39"),
#                    shex("ad142c11579dd95e 41f3c1f324dabc25"
#                         "5864d920f1b65759 d8f560d4948d4477"
#                         "58dfdcf77aa9f625 81c7ff572a037f81"
#                         "0cb1a9c4b3ca6ed6 38179b77"),
#                    shex("cafebabefacedbaddecaf888"),
#                    shex("4e4b178d8fe26fdc95e2e7246dd94bec"))
#
#
# class EAX(TestCase):
#
#     def _test(self, cipher: type[nettle.AesFamilyCipher],
#               key: bytes, authtext: bytes, cleartext: bytes, ciphertext: bytes,
#               nonce: bytes, digest: bytes):
#         self.assertEqual(len(cleartext), len(ciphertext))
#
#         c = cipher(key)
#         self.assertEqual(c.key_size, len(key))
#         eax = nettle.EAX(c, nonce)
#         eax.update(authtext)
#
#         self.assertEqual(eax.encrypt(cleartext), ciphertext)
#         self.assertEqual(eax.digest(), digest)
#         self.assertEqual(shex(eax.hexdigest()), digest)
#         self.assertEqual(eax.digest(), digest)
#
#         with pytest.raises(nettle.KeyLenError):
#             c = cipher(encrypt_key=key + b'a')
#         with pytest.raises(nettle.KeyLenError):
#             c = cipher()
#             c.set_encrypt_key(key[:-1])
#         with pytest.raises(nettle.KeyLenError):
#             c = cipher()
#             c.set_decrypt_key(key[:-1])
#
#         with pytest.raises(nettle.NotInitializedError):
#             c = cipher()
#             eax = nettle.EAX(c, nonce)
#             eax.encrypt(cleartext)
#         with pytest.raises(nettle.NotInitializedError):
#             c = cipher()
#             eax = nettle.EAX(c, nonce)
#             eax.decrypt(cleartext)
#
#     def test_aes128_eax():
#         _test(nettle.AES128,
#                    shex("01F74AD64077F2E704C0F60ADA3DD523"),
#                    shex("234A3463C1264AC6"),
#                    shex("1A47CB4933"),
#                    shex("D851D5BAE0"),
#                    shex("70C3DB4F0D26368400A10ED05D2BFF5E"),
#                    shex("3A59F238A23E39199DC9266626C40F80"))
#         _test(nettle.AES128,
#                    shex("233952DEE4D5ED5F9B9C6D6FF80FF478"),
#                    shex("6BFB914FD07EAE6B"),
#                    shex(""),
#                    shex(""),
#                    shex("62EC67F9C3A4A407FCB2A8C49031A8B3"),
#                    shex("E037830E8389F27B025A2D6527E79D01"))
#
#
# class CCM(TestCase):
#
#     def _test(self, cipher: type[nettle.AesFamilyCipher],
#               key: bytes, nonce: bytes, authtext: bytes,
#               cleartext: bytes, cipherdigest: bytes):
#         clen = len(cleartext)
#         ciphertext = cipherdigest[:clen]
#         digest = cipherdigest[clen:]
#         self.assertEqual(len(cleartext), len(ciphertext))
#
#         c = cipher(key)
#         self.assertEqual(c.key_size, len(key))
#         ccm = nettle.CCM(c, nonce, len(authtext), len(cleartext), len(digest))
#         ccm.update(authtext)
#
#         self.assertEqual(ccm.encrypt(cleartext), ciphertext)
#         self.assertEqual(ccm.digest(), digest)
#         self.assertEqual(shex(ccm.hexdigest()), digest)
#         self.assertEqual(ccm.digest(), digest)
#
#         with pytest.raises(nettle.KeyLenError):
#             c = cipher(encrypt_key=key + b'a')
#         with pytest.raises(nettle.KeyLenError):
#             c = cipher()
#             c.set_encrypt_key(key[:-1])
#         with pytest.raises(nettle.KeyLenError):
#             c = cipher()
#             c.set_decrypt_key(key[:-1])
#
#         with pytest.raises(nettle.NotInitializedError):
#             c = cipher()
#             ccm = nettle.CCM(c, nonce, len(authtext), len(cleartext),
#                              len(digest))
#             ccm.encrypt(cleartext)
#         with pytest.raises(nettle.NotInitializedError):
#             c = cipher()
#             ccm = nettle.CCM(c, nonce, len(authtext), len(cleartext),
#                              len(digest))
#             ccm.decrypt(cleartext)
#
#         with pytest.raises(nettle.LenMismatch):
#             c = cipher(key)
#             ccm = nettle.CCM(c, nonce, len(authtext), len(cleartext) - 1,
#                              len(digest))
#             ccm.update(authtext)
#             ccm.encrypt(cleartext)
#
#         with pytest.raises(nettle.LenMismatch):
#             c = cipher(key)
#             ccm = nettle.CCM(c, nonce, len(authtext) - 1, len(cleartext),
#                              len(digest))
#             ccm.update(authtext)
#             ccm.encrypt(cleartext)
#
#     def test_aes128_ccm():
#         _test(nettle.AES128,
#                    shex("404142434445464748494a4b4c4d4e4f"),
#                    shex("10111213141516"),
#                    shex("0001020304050607"),
#                    shex("20212223"),
#                    shex("7162015b 4dac255d"))
#         _test(nettle.AES256,
#                    shex("000000000000000000000000"
#                         "000000000000000000000000"
#                         "0000000000000000"),
#                    shex("000000000000000000000000"),
#                    shex(""),
#                    shex("00000000000000000000000000000000"),
#                    shex("c1944044c8e7aa95d2de9513c7f3dd8c"
#                         "4b0a3e5e51f151eb0ffae7c43d010fdb"))
#
