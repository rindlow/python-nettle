import nettle.cipher_modes
import nettle.ciphers
import pytest

from .utils import shex


@pytest.mark.parametrize(
    ("cipher", "ciphermode", "key", "cleartext", "ciphertext", "iv"),
    [
        (
            nettle.ciphers.AES128,
            nettle.cipher_modes.CBC,
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
            nettle.ciphers.AES192,
            nettle.cipher_modes.CBC,
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
            nettle.ciphers.AES256,
            nettle.cipher_modes.CBC,
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
def test_cipher_mode(
    cipher: type[nettle.ciphers.BlockCipher],
    ciphermode: type[nettle.cipher_modes.CipherMode],
    key: bytes,
    cleartext: bytes,
    ciphertext: bytes,
    iv: bytes,
) -> None:

    assert len(cleartext) == len(ciphertext)

    c = cipher()
    c.set_encrypt_key(key)
    cm = ciphermode(c, iv)
    assert cm.encrypt(cleartext) == ciphertext

    c = cipher()
    c.set_decrypt_key(key)
    cm = ciphermode(c, iv)
    assert cm.decrypt(ciphertext) == cleartext

    c = cipher()
    cm = ciphermode(c, iv)
    with pytest.raises(nettle.NotInitializedError):
        cm.encrypt(cleartext)
    with pytest.raises(nettle.NotInitializedError):
        c.decrypt(cleartext)


@pytest.mark.parametrize(
    ("cipher", "ciphermode", "key", "cleartext", "ciphertext", "iv"),
    [
        (
            nettle.ciphers.AES128,
            nettle.cipher_modes.CFB8,
            shex("2b7e151628aed2a6abf7158809cf4f3c"),
            shex("6bc1bee22e409f96e93d7e117393172aae2d"),
            shex("3b79424c9c0dd436bace9e0ed4586a4f32b9"),
            shex("000102030405060708090a0b0c0d0e0f"),
        ),
        (
            nettle.ciphers.AES192,
            nettle.cipher_modes.CFB,
            shex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
            shex(
                "6bc1bee22e409f96e93d7e117393172a"
                "ae2d8a571e03ac9c9eb76fac45af8e51"
                "30c81c46a35ce411e5fbc1191a0a52ef"
                "f69f2445df4f9b17ad2b417be66c3710"
            ),
            shex(
                "cdc80d6fddf18cab34c25909c99a4174"
                "67ce7f7f81173621961a2b70171d3d7a"
                "2e1e8a1dd59b88b1c8e60fed1efac4c9"
                "c05f9f9ca9834fa042ae8fba584b09ff"
            ),
            shex("000102030405060708090a0b0c0d0e0f"),
        ),
    ],
)
def test_cipher_mode_decrypt_with_encrypt_key(
    cipher: type[nettle.ciphers.BlockCipher],
    ciphermode: type[nettle.cipher_modes.CipherMode],
    key: bytes,
    cleartext: bytes,
    ciphertext: bytes,
    iv: bytes,
) -> None:

    assert len(cleartext) == len(ciphertext)

    c = cipher()
    c.set_encrypt_key(key)
    cm = ciphermode(c, iv)
    assert cm.encrypt(cleartext) == ciphertext

    c = cipher()
    c.set_encrypt_key(key)
    cm = ciphermode(c, iv)
    assert cm.decrypt(ciphertext) == cleartext

    c = cipher()
    cm = ciphermode(c, iv)
    with pytest.raises(nettle.NotInitializedError):
        cm.encrypt(cleartext)


@pytest.mark.parametrize(
    ("cipher", "ciphermode", "key", "cleartext", "ciphertext", "iv"),
    [
        (
            nettle.ciphers.AES128,
            nettle.cipher_modes.CTR,
            shex("2b7e151628aed2a6abf7158809cf4f3c"),
            shex(
                "6bc1bee22e409f96e93d7e117393172a"
                "ae2d8a571e03ac9c9eb76fac45af8e51"
                "30c81c46a35ce411e5fbc1191a0a52ef"
                "f69f2445df4f9b17ad2b417be66c3710"
            ),
            shex(
                "874d6191b620e3261bef6864990db6ce"
                "9806f66b7970fdff8617187bb9fffdff"
                "5ae4df3edbd5d35e5b4f09020db03eab"
                "1e031dda2fbe03d1792170a0f3009cee"
            ),
            shex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        ),
        (
            nettle.ciphers.AES192,
            nettle.cipher_modes.CTR,
            shex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
            shex(
                "6bc1bee22e409f96e93d7e117393172a"
                "ae2d8a571e03ac9c9eb76fac45af8e51"
                "30c81c46a35ce411e5fbc1191a0a52ef"
                "f69f2445df4f9b17ad2b417be66c3710"
            ),
            shex(
                "1abc932417521ca24f2b0459fe7e6e0b"
                "090339ec0aa6faefd5ccc2c6f4ce8e94"
                "1e36b26bd1ebc670d1bd1d665620abf7"
                "4f78a7f6d29809585a97daec58c6b050"
            ),
            shex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        ),
        (
            nettle.ciphers.AES256,
            nettle.cipher_modes.CTR,
            shex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            shex(
                "6bc1bee22e409f96e93d7e117393172a"
                "ae2d8a571e03ac9c9eb76fac45af8e51"
                "30c81c46a35ce411e5fbc1191a0a52ef"
                "f69f2445df4f9b17ad2b417be66c3710"
            ),
            shex(
                "601ec313775789a5b7a7f504bbf3d228"
                "f443e3ca4d62b59aca84e990cacaf5c5"
                "2b0930daa23de94ce87017ba2d84988d"
                "dfc9c58db67aada613c2dd08457941a6"
            ),
            shex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        ),
    ],
)
def test_ctr(
    cipher: type[nettle.ciphers.BlockCipher],
    ciphermode: type[nettle.cipher_modes.CTR],
    key: bytes,
    cleartext: bytes,
    ciphertext: bytes,
    iv: bytes,
) -> None:

    assert len(cleartext) == len(ciphertext)

    c = cipher()
    c.set_encrypt_key(key)
    cm = ciphermode(c, iv)
    assert cm.crypt(cleartext) == ciphertext

    c = cipher()
    c.set_encrypt_key(key)
    cm = ciphermode(c, iv)
    assert cm.crypt(ciphertext) == cleartext

    c = cipher()
    cm = ciphermode(c, iv)
    with pytest.raises(nettle.NotInitializedError):
        cm.crypt(cleartext)


@pytest.mark.parametrize(
    ("cipher", "key", "tweak", "cleartext", "ciphertext"),
    [
        (
            nettle.ciphers.AES128,
            shex("a1b90cba3f06ac353b2c343876081762090923026e91771815f29dab01932f2f"),
            shex("4faef7117cda59c66e4b92013e768ad5"),
            shex("ebabce95b14d3c8d6fb350390790311c"),
            shex("778ae8b43cb98d5a825081d5be471c63"),
        ),
        (
            nettle.ciphers.AES128,
            shex("394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4"),
            shex("4b15c684a152d485fe9937d39b168c29"),
            shex("2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0"),
            shex("f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e"),
        ),
        (
            nettle.ciphers.AES256,
            shex(
                "266c336b3b01489f3267f52835fd92f6"
                "74374b88b4e1ebd2d36a5f457581d9d0"
                "42c3eef7b0b7e5137b086496b4d9e6ac"
                "658d7196a23f23f036172fdb8faee527"
            ),
            shex("06b209a7a22f486ecbfadb0f3137ba42"),
            shex(
                "ca7d65ef8d3dfad345b61ccddca1ad81"
                "de830b9e86c7b426d76cb7db766852d9"
                "81c6b21409399d78f42cc0b33a7bbb06"
            ),
            shex(
                "c73256870cc2f4dd57acc74b5456dbd7"
                "76912a128bc1f77d72cdebbf270044b7"
                "a43ceed29025e1e8be211fa3c3ed002d"
            ),
        ),
    ],
)
def test_xts(
    cipher: type[nettle.ciphers.BlockCipher],
    key: bytes,
    tweak: bytes,
    cleartext: bytes,
    ciphertext: bytes,
) -> None:

    assert len(cleartext) == len(ciphertext)
    assert len(key) == 2 * cipher.key_size
    assert len(tweak) == 16

    primary_key = key[: cipher.key_size]
    tweak_key = key[cipher.key_size :]

    c = cipher()
    c.set_encrypt_key(primary_key)
    cm = nettle.cipher_modes.XTS(c, tweak_key)
    assert cm.encrypt_message(cleartext, tweak) == ciphertext

    c.set_decrypt_key(primary_key)
    assert cm.decrypt_message(ciphertext, tweak) == cleartext

    with pytest.raises(NotImplementedError):
        cm.encrypt(cleartext)
    with pytest.raises(NotImplementedError):
        cm.decrypt(cleartext)
