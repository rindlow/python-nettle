import nettle.aead
import nettle.ciphers
import pytest

from .utils import shex


@pytest.mark.parametrize(
    ("cipher", "mode", "key", "authtext", "cleartext", "ciphertext", "iv", "digest"),
    [
        (
            nettle.ciphers.AES128,
            nettle.aead.GCM,
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
    cipher: type[nettle.ciphers.BlockCipher],
    mode: type[nettle.aead.AEAD],
    key: bytes,
    authtext: bytes,
    cleartext: bytes,
    ciphertext: bytes,
    iv: bytes,
    digest: bytes,
) -> None:
    assert len(cleartext) == len(ciphertext)

    c = cipher()
    c.set_encrypt_key(key)
    assert c.key_size == len(key)
    aead = mode(c, iv)
    aead.update(authtext)
    assert aead.encrypt(cleartext) == ciphertext
    assert aead.digest() == digest

    c = cipher()
    c.set_encrypt_key(key)
    aead = mode(c, iv)
    aead.update(authtext)
    aead.encrypt(cleartext)
    assert shex(aead.hexdigest()) == digest

    c = cipher()
    c.set_encrypt_key(key)
    aead = mode(c, iv)
    aead.update(authtext)
    assert aead.decrypt(ciphertext) == cleartext

    c = cipher()
    with pytest.raises(nettle.NotInitializedError):
        aead = mode(c, iv)
