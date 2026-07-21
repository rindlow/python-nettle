import nettle.ciphers
import nettle.randomness

import pytest

from .utils import sdata, shex


@pytest.fixture(scope="module")
def yarrow() -> nettle.randomness.Yarrow256:
    return nettle.randomness.Yarrow256()


@pytest.mark.parametrize(
    ("cipher", "key", "cleartext", "ciphertext"),
    [
        (
            nettle.ciphers.AES128,
            shex("0001020305060708 0A0B0C0D0F101112"),
            shex("506812A45F08C889 B97F5980038B8359"),
            shex("D8F532538289EF7D 06B506A4FD5BE9C9"),
        ),
        (
            nettle.ciphers.AES192,
            shex("0001020305060708 0A0B0C0D0F10111214151617191A1B1C"),
            shex("2D33EEF2C0430A8A 9EBF45E809C40BB6"),
            shex("DFF4945E0336DF4C 1C56BC700EFF837F"),
        ),
        (
            nettle.ciphers.AES256,
            shex("0001020305060708 0A0B0C0D0F10111214151617191A1B1C 1E1F202123242526"),
            shex("834EADFCCAC7E1B30664B1ABA44815AB"),
            shex("1946DABF6A03A2A2 C3D0B05080AED6FC"),
        ),
        (
            nettle.ciphers.Camellia128,
            shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
            shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
            shex("67 67 31 38 54 96 69 73 08 57 06 56 48 ea be 43"),
        ),
        (
            nettle.ciphers.Camellia192,
            shex("0123456789abcdeffedcba98765432100011223344556677"),
            shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
            shex("b4 99 34 01 b3 e9 96 f8 4e e5 ce e7 d7 9b 09 b9"),
        ),
        (
            nettle.ciphers.Camellia256,
            shex(
                "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
                "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"
            ),
            shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
            shex("9a cc 23 7d ff 16 d7 6c 20 ef 7c 91 9e 3a 75 09"),
        ),
    ],
)
def test_cipher(
    cipher: type[nettle.ciphers.Cipher],
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

    c = cipher()
    c.set_encrypt_key(key)
    assert c.encrypt(cleartext) == ciphertext
    c = cipher()
    c.set_decrypt_key(key)
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
            nettle.ciphers.AES128,
            shex("0001020305060708 0A0B0C0D0F101112"),
            shex("506812A45F08C889 B97F5980038B8359"),
            shex("D8F532538289EF7D 06B506A4FD5BE9C9"),
        )
    ],
)
def test_invert(
    cipher: type[nettle.ciphers.InvertibleKeyCipher],
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
            nettle.ciphers.AES128,
            shex("0001020304050607 08090A0B0C0D0E0F"),
            shex("0011223344556677 8899AABBCCDDEEFF"),
            shex("1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"),
        ),
        (
            nettle.ciphers.AES192,
            shex("0001020304050607 08090A0B0C0D0E0F 1011121314151617"),
            shex("0011223344556677 8899AABBCCDDEEFF"),
            shex("96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D"),
        ),
        (
            nettle.ciphers.AES256,
            shex("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
            shex("0011223344556677 8899AABBCCDDEEFF"),
            shex("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7"),
        ),
        (
            nettle.ciphers.Camellia128,
            shex("01 23 45 67 89 ab cd effe dc ba 98 76 54 32 10"),
            shex("01 23 45 67 89 ab cd effe dc ba 98 76 54 32 10"),
            shex("67 67 31 38 54 96 69 7308 57 06 56 48 ea be 43"),
        ),
    ],
)
def test_keywrap(
    cipher: type[nettle.ciphers.KeyWrapCipher],
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


def test_arcfour() -> None:
    key = shex("01234567 89ABCDEF 00000000 00000000")
    cleartext = shex("01234567 89ABCDEF")
    ciphertext = shex("69723659 1B5242B1")

    assert len(cleartext) == len(ciphertext)
    c = nettle.ciphers.Arcfour()
    with pytest.raises(nettle.NotInitializedError):
        c.crypt(cleartext)
    assert c.min_key_size <= len(key) <= c.max_key_size
    c.set_key(key)
    assert c.crypt(cleartext) == ciphertext
    c.set_key(key)
    assert c.crypt(ciphertext) == cleartext
    c.set_key(key)
    assert c.decrypt(ciphertext) == cleartext

    c = nettle.ciphers.Arcfour(key=key)
    assert c.crypt(cleartext) == ciphertext
    c = nettle.ciphers.Arcfour(key=key)
    assert c.crypt(ciphertext) == cleartext

    c = nettle.ciphers.Arcfour()
    with pytest.raises(nettle.NotInitializedError):
        c.crypt(cleartext)


@pytest.mark.parametrize(
    ("cipher", "key", "cleartext", "ciphertext"),
    [
        (
            nettle.ciphers.Arctwo,
            shex("ffffffff ffffffff"),
            shex("ffffffff ffffffff"),
            shex("278b27e4 2e2f0d49"),
        ),
        (
            nettle.ciphers.Blowfish,
            sdata("abcdefghijklmnopqrstuvwxyz"),
            sdata("BLOWFISH"),
            shex("32 4E D0 FE F4 13 A2 03"),
        ),
        (
            nettle.ciphers.Cast128,
            shex("01 23 45 67 12 34 56 78 23 45 67 89 34 56 78 9A"),
            shex("01 23 45 67 89 AB CD EF"),
            shex("23 8B 4F E5 84 7E 44 B2"),
        ),
        (
            nettle.ciphers.Serpent,
            shex("0000000000000000 0000000000000000"),
            shex("D29D576FCEA3A3A7 ED9099F29273D78E"),
            shex("B2288B968AE8B086 48D1CE9606FD992D"),
        ),
        (
            nettle.ciphers.Serpent,
            shex("0000000000000000 0000000000000000 0000000000000000"),
            shex("D29D576FCEABA3A7 ED9899F2927BD78E"),
            shex("130E353E1037C224 05E8FAEFB2C3C3E9"),
        ),
        (
            nettle.ciphers.Serpent,
            shex("0000000000000000 00000000000000000000000000000000 0000000000000000"),
            shex("D095576FCEA3E3A7 ED98D9F29073D78E"),
            shex("B90EE5862DE69168 F2BDD5125B45472B"),
        ),
        (
            nettle.ciphers.Twofish,
            shex("0000000000000000 0000000000000000"),
            shex("0000000000000000 0000000000000000"),
            shex("9F589F5CF6122C32 B6BFEC2F2AE8C35A"),
        ),
        (
            nettle.ciphers.Twofish,
            shex("0123456789ABCDEF FEDCBA98765432100011223344556677"),
            shex("0000000000000000 0000000000000000"),
            shex("CFD1D2E5A9BE9CDF 501F13B892BD2248"),
        ),
        (
            nettle.ciphers.Twofish,
            shex("0123456789ABCDEF FEDCBA98765432100011223344556677 8899AABBCCDDEEFF"),
            shex("0000000000000000 0000000000000000"),
            shex("37527BE0052334B8 9F0CFCCAE87CFA20"),
        ),
    ],
)
def test_single_key_cipher(
    cipher: type[nettle.ciphers.SingleKeyCipher],
    key: bytes,
    cleartext: bytes,
    ciphertext: bytes,
) -> None:

    assert len(cleartext) == len(ciphertext)
    c = cipher()
    with pytest.raises(nettle.NotInitializedError):
        c.encrypt(cleartext)
    c.set_key(key)
    assert c.encrypt(cleartext) == ciphertext
    assert c.decrypt(ciphertext) == cleartext


def test_bcrypt(yarrow: nettle.randomness.Random) -> None:
    salt = yarrow.random(nettle.ciphers.Blowfish.bcrypt_binsalt_size)
    hashed = nettle.ciphers.Blowfish.bcrypt_hash("U*U", "2a", 5, salt)
    assert nettle.ciphers.Blowfish.bcrypt_verify("U*U", hashed)


@pytest.mark.parametrize(
    ("key", "hashed", "expected"),
    [
        ("U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", True),
        ("", "$2a$03$CCCCCCCCCCCCCCCCCCCCC.", False),
    ],
)
def test_bcrypt_verify(key: str, hashed: str, expected: bool) -> None:
    assert nettle.ciphers.Blowfish.bcrypt_verify(key, hashed) == expected


@pytest.mark.parametrize(
    ("cipher", "key", "cleartext", "ciphertext"),
    [
        (
            nettle.ciphers.Camellia128,
            shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
            shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
            shex("67 67 31 38 54 96 69 73 08 57 06 56 48 ea be 43"),
        ),
        (
            nettle.ciphers.Camellia192,
            shex(
                "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 1000 11 22 33 44 55 66 77"
            ),
            shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
            shex("b4 99 34 01 b3 e9 96 f8 4e e5 ce e7 d7 9b 09 b9"),
        ),
        (
            nettle.ciphers.Camellia256,
            shex(
                "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
                "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"
            ),
            shex("01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"),
            shex("9a cc 23 7d ff 16 d7 6c 20 ef 7c 91 9e 3a 75 09"),
        ),
        pytest.param(
            nettle.ciphers.SM4,
            shex("0123456789ABCDEF FEDCBA9876543210"),
            shex("0123456789ABCDEF FEDCBA9876543210"),
            shex("681EDF34D206965E 86B3E94F536E4246"),
            marks=pytest.mark.skipif(
                nettle.version < (3, 9), reason="SM4 was introduced in nettle 3.9"
            ),
        ),
    ],
)
def test_doublekey_singlefunc(
    cipher: type[nettle.ciphers.CamelliaFamilyCipher | nettle.ciphers.SM4],
    key: bytes,
    cleartext: bytes,
    ciphertext: bytes,
) -> None:
    assert len(cleartext) == len(ciphertext)
    c = cipher()
    with pytest.raises(nettle.NotInitializedError):
        c.crypt(cleartext)
    assert len(key) == c.key_size
    c.set_encrypt_key(key)
    assert c.crypt(cleartext) == ciphertext
    c.set_decrypt_key(key)
    assert c.crypt(ciphertext) == cleartext

    c = cipher(encrypt_key=key)
    assert c.crypt(cleartext) == ciphertext
    c = cipher(decrypt_key=key)
    assert c.crypt(ciphertext) == cleartext

    with pytest.raises(nettle.KeyLenError):
        cipher(encrypt_key=key[:-1])


def test_camellia_invert() -> None:
    cipher = nettle.ciphers.Camellia128
    key = shex("01 23 45 67 89 ab cd effe dc ba 98 76 54 32 10")
    cleartext = shex("01 23 45 67 89 ab cd effe dc ba 98 76 54 32 10")
    ciphertext = shex("67 67 31 38 54 96 69 7308 57 06 56 48 ea be 43")
    assert len(cleartext) == len(ciphertext)
    c = cipher(encrypt_key=key)
    assert c.crypt(cleartext) == ciphertext
    c.invert_key()
    assert c.crypt(ciphertext) == cleartext


@pytest.mark.parametrize(
    ("cipher", "key", "nonce", "expected"),
    [
        (
            nettle.ciphers.ChaCha,
            shex("0000000000000000000000000000000000000000000000000000000000000000"),
            shex("0000000000000000"),
            shex(
                "76b8e0ada0f13d90 405d6ae55386bd28"
                "bdd219b8a08ded1a a836efcc8b770dc7"
                "da41597c5157488d 7724e03fb8d84a37"
                "6a43b8f41518a11c c387b669b2ee6586"
                "9f07e7be5551387a 98ba977c732d080d"
                "cb0f29a048e36569 12c6533e32ee7aed"
                "29b721769ce64e43 d57133b074d839d5"
                "31ed1f28510afb45 ace10a1f4b794d6f"
            ),
        ),
        (
            nettle.ciphers.Salsa20_128,
            shex("80000000000000000000000000000000"),
            shex("0000000000000000"),
            shex("4DFA5E481DA23EA0"),
        ),
        (
            nettle.ciphers.Salsa20_256,
            shex("8000000000000000000000000000000000000000000000000000000000000000"),
            shex("0000000000000000"),
            shex("E3BE8FDD8BECA2E3"),
        ),
    ],
)
def test_nonce_cipher(
    cipher: type[nettle.ciphers.ChaCha], key: bytes, nonce: bytes, expected: bytes
) -> None:
    data = b"\0" * len(expected)
    c = cipher(key=key, nonce=nonce)
    assert c.crypt(data) == expected
    c = cipher(key=key, nonce=nonce)
    assert c.crypt(expected) == data

    c = cipher()
    with pytest.raises(nettle.NotInitializedError):
        c.crypt(data)
    c.set_key(key)
    with pytest.raises(nettle.NotInitializedError):
        c.crypt(data)
    c.set_nonce(nonce)
    assert c.crypt(data) == expected


@pytest.mark.parametrize(
    ("key", "nonce", "expected", "counter"),
    [
        (
            shex("0001020304050607 08090a0b0c0d0e0f1011121314151617 18191a1b1c1d1e1f"),
            shex("000000090000004a 00000000"),
            shex(
                "10f1e7e4d13b5915 500fdd1fa32071c4"
                "c7d1f4c733c06803 0422aa9ac3d46c4e"
                "d2826446079faa09 14c2d705d98b02a2"
                "b5129cd1de164eb9 cbd083e8a2503c4e"
            ),
            shex("01000000"),
        ),
        (
            shex("0001020304050607 08090a0b0c0d0e0f1011121314151617 18191a1b1c1d1e1f"),
            shex("0000004a00000000"),
            shex(
                "10f1e7e4d13b5915 500fdd1fa32071c4"
                "c7d1f4c733c06803 0422aa9ac3d46c4e"
                "d2826446079faa09 14c2d705d98b02a2"
                "b5129cd1de164eb9 cbd083e8a2503c4e"
            ),
            shex("0100000000000009"),
        ),
    ],
)
def test_chacha_with_counter(
    key: bytes, nonce: bytes, expected: bytes, counter: bytes
) -> None:
    c = nettle.ciphers.ChaCha(key)
    data = b"\0" * (len(expected))
    if len(nonce) == c.nonce_size:
        c.set_nonce(nonce)
        c.set_counter(counter)
        assert c.crypt(data) == expected
    else:
        c.set_nonce96(nonce)
        c.set_counter32(counter)
        assert c.crypt32(data) == expected


@pytest.mark.parametrize(
    ("cipher", "key", "cleartext", "ciphertext"),
    [
        (
            nettle.ciphers.DES,
            shex("01234567 89ABCDEF"),
            shex("01234567 89ABCDE7"),
            shex("C9574425 6A5ED31D"),
        ),
        (
            nettle.ciphers.DES3,
            shex(
                "3e 0b 10 b0 5d 49 c2 546b 46 e0 75 8a 91 61 85cb 04 07 d3 20 16 cb a2"
            ),
            sdata("Now is t"),
            shex("0a 5d b5 2d 85 74 d1 c9"),
        ),
    ],
)
def test_des(
    cipher: type[nettle.ciphers.DES], key: bytes, cleartext: bytes, ciphertext: bytes
) -> None:
    assert len(cleartext) == len(ciphertext)
    c = cipher()
    assert c.check_parity(key)
    with pytest.raises(nettle.NotInitializedError):
        c.encrypt(cleartext)
    c.set_key(key)
    assert c.encrypt(cleartext) == ciphertext
    assert c.decrypt(ciphertext) == cleartext

    c = cipher(key=key)
    assert c.encrypt(cleartext) == ciphertext
    c = cipher(key=key)
    assert c.decrypt(ciphertext) == cleartext

    key2 = bytearray(key)
    key2[-1] ^= 1
    assert not c.check_parity(bytes(key2))
    assert c.check_parity(c.fix_parity(bytes(key2)))


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
