import nettle.macs
import pytest

from .utils import sdata, shex


@pytest.mark.parametrize(
    ("macclass", "key", "msg", "expected"),
    [
        (
            nettle.macs.HMAC_SHA1,
            shex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            sdata("Hi There"),
            shex("b617318655057264e28bc0b6fb378c8ef146be00"),
        ),
        (
            nettle.macs.HMAC_SHA256,
            shex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            sdata("Hi There"),
            shex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        ),
    ],
)
def test_without_nonce(
    macclass: type[nettle.macs.MAC], key: bytes, msg: bytes, expected: bytes
) -> None:
    h = macclass(key=key)
    assert h.digest_size > 0
    h.update(msg)
    assert h.digest() == expected
    h.update(msg)
    assert shex(h.hexdigest()) == expected

    h = macclass()
    h.set_key(key)
    h.update(msg)
    assert h.digest() == expected

    h = macclass()
    with pytest.raises(nettle.NotInitializedError):
        h.update(msg)


def xtest_with_nonce(
    macclass: type[nettle.macs.NonceMAC],
    key: bytes,
    msg: bytes,
    expected: bytes,
    nonce: bytes,
) -> None:
    h = macclass(key=key, nonce=nonce)
    h.update(msg)
    assert h.digest() == expected
    h.update(msg)
    assert shex(h.hexdigest()) == expected

    h = macclass()
    h.set_key(key)
    h.set_nonce(nonce)
    h.update(msg)
    assert h.digest() == expected

    h = macclass()
    with pytest.raises(nettle.NotInitializedError):
        h.update(msg)


@pytest.mark.parametrize(
    ("macclass", "iterations", "password", "salt", "length", "expected"),
    [
        (
            nettle.macs.HMAC_SHA1,
            1,
            b"password",
            b"salt",
            20,
            shex("0c60c80f961f0e71f3a9b524af6012062fe037a6"),
        ),
        (
            nettle.macs.HMAC_SHA1,
            2,
            b"password",
            b"salt",
            20,
            shex("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
        ),
        (
            nettle.macs.HMAC_SHA1,
            4096,
            b"password",
            b"salt",
            20,
            shex("4b007901b765489abead49d926f721d065a429c1"),
        ),
        (
            nettle.macs.HMAC_SHA256,
            80000,
            b"Password",
            b"NaCl",
            16,
            shex("4ddcd8f60b98be21830cee5ef22701f9"),
        ),
        (
            nettle.macs.HMAC_SHA512,
            50,
            b"passwordPASSWORDpassword",
            b"salt\0\0\0",
            64,
            shex(
                "016871a4c4b75f96857fd2b9f8ca28023b30ee2a39f5adcac8c9375f9bda1ccd"
                "1b6f0b2fc3adda505412e79d890056c62e524c7d51154b1a8534575bd02dee39"
            ),
        ),
    ],
)
def test_pbkdf2(
    macclass: type[nettle.macs.MAC],
    iterations: int,
    password: bytes,
    salt: bytes,
    length: int,
    expected: bytes,
) -> None:
    mac = macclass(key=password)
    assert mac.pbkdf2(iterations, salt, length) == expected


#    def test_hmac_sha512(self):
#        self._test_without_nonce(
#            nettle.macs.HMAC_SHA512,
#            shex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
#            sdata("Hi There"),
#            shex(
#                "87aa7cdea5ef619d4ff0b4241a1d6cb0"
#                "2379f4e2ce4ec2787ad0b30545e17cde"
#                "daa833b7d6b8a702038b274eaea3f4e4"
#                "be9d914eeb61f1702e696c203a126854"
#            ),
#        )
#
#    def test_umac32(self):
#        self._test_with_nonce(
#            nettle.macs.UMAC32,
#            key=sdata("abcdefghijklmnop"),
#            msg=sdata(""),
#            digest=shex("113145FB"),
#            nonce=sdata("bcdefghi"),
#        )
#
#    def test_umac64(self):
#        self._test_with_nonce(
#            nettle.macs.UMAC64,
#            key=sdata("abcdefghijklmnop"),
#            msg=sdata(""),
#            digest=shex("6E155FAD26900BE1"),
#            nonce=sdata("bcdefghi"),
#        )
#
#    def test_umac96(self):
#        self._test_with_nonce(
#            nettle.macs.UMAC96,
#            key=sdata("abcdefghijklmnop"),
#            msg=sdata(""),
#            digest=shex("32fedb100c79ad58f07ff764"),
#            nonce=sdata("bcdefghi"),
#        )
#
#    def test_umac128(self):
#        self._test_with_nonce(
#            nettle.macs.UMAC128,
#            key=sdata("abcdefghijklmnop"),
#            msg=sdata(""),
#            digest=shex("32fedb100c79ad58f07ff7643cc60465"),
#            nonce=sdata("bcdefghi"),
#        )
#
#    def test_poly1305_aes(self):
#        self._test_with_nonce(
#            nettle.macs.Poly1305_AES,
#            key=shex(
#                "75deaa25c09f208e1dc4ce6b5cad3fbfa0f3080000f46400d0c7e9076c834403"
#            ),
#            nonce=shex("61ee09218d29b0aaed7e154a2c5509cc"),
#            msg=shex(""),
#            digest=shex("dd3fab2251f11ac759f0887129cc2ee7"),
#        )
#
