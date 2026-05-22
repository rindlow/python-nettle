import nettle.cipher_modes
import nettle.ciphers
import pytest

from .utils import shex


@pytest.mark.parametrize(
    ("cipher", "key", "cleartext", "ciphertext", "iv"),
    [
        (
            nettle.ciphers.AES128,
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
    cipher: type[nettle.ciphers.BlockCipher],
    key: bytes,
    cleartext: bytes,
    ciphertext: bytes,
    iv: bytes,
) -> None:

    assert len(cleartext) == len(ciphertext)

    c = cipher()
    c.set_encrypt_key(key)
    cbc = nettle.cipher_modes.CBC(c, iv)
    assert cbc.encrypt(cleartext) == ciphertext

    c = cipher()
    c.set_decrypt_key(key)
    cbc = nettle.cipher_modes.CBC(c, iv)
    assert cbc.decrypt(ciphertext) == cleartext

    c = cipher()
    cbc = nettle.cipher_modes.CBC(c, iv)
    with pytest.raises(nettle.NotInitializedError):
        cbc.encrypt(cleartext)
    with pytest.raises(nettle.NotInitializedError):
        cbc.decrypt(cleartext)
