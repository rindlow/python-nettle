#
# rsa.py
#
# Copyright (C) 2017-2026 Henrik Rindlöw
#
# This file is part of python-nettle.
#
# Python-nettle is free software: you can redistribute it and/or
# modify it under the terms of either:
#
#   * the GNU Lesser General Public License as published by the Free
#     Software Foundation; either version 3 of the License, or (at your
#     option) any later version.
#
# or
#
#   * the GNU General Public License as published by the Free
#     Software Foundation; either version 2 of the License, or (at your
#     option) any later version.
#
# or both in parallel, as here.
#
# Python-nettle is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received copies of the GNU General Public License and
# the GNU Lesser General Public License along with this program.  If
# not, see http://www.gnu.org/licenses/.

"""Nettle RSA Public Key implementation."""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING, Self

from nettle.asn1 import (
    OID,
    BitString,
    Integer,
    Null,
    OctetString,
)
from nettle.asn1types import (
    AlgorithmIdentifier,
    PrivateKeyInfo,
    RSAPrivateKey,
    RSAPublicKey,
    SubjectPublicKeyInfo,
)
from nettle.exceptions import RSAError
from nettle.libgmp import libgmp
from nettle.libhogweed import libhogweed
from nettle.libnettle import libnettle
from nettle.pubkey import KeyPair, PubKey
from nettle.pubkey.pubkey import PKParam
from nettle.randomness import Random, Yarrow256

if TYPE_CHECKING:
    from nettle.hashes import SHA1, SHA256, SHA512

__all__ = ["RSAKeyPair", "RSAPubKey"]


class _MPZStruct(ctypes.Structure):
    _fields_ = [
        ("_mp_alloc", ctypes.c_int),
        ("_mp_size", ctypes.c_int),
        ("_mp_d", ctypes.c_void_p),
    ]


_MPZ_T = _MPZStruct * 1


class _RSAPrivateKey(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_size_t),
        ("d", _MPZ_T),
        ("p", _MPZ_T),
        ("q", _MPZ_T),
        ("a", _MPZ_T),
        ("b", _MPZ_T),
        ("c", _MPZ_T),
    ]


class _RSAPublicKey(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_size_t),
        ("n", _MPZStruct * 1),
        ("e", _MPZ_T),
    ]


def _mpz_to_int(mpz: ctypes.Array[_MPZStruct]) -> int:
    datalen = libgmp.gmp["__gmpz_sizeinbase"](ctypes.byref(mpz), 256)
    data = ctypes.create_string_buffer(datalen)
    count = ctypes.c_size_t()
    libgmp.gmp["__gmpz_export"](data, ctypes.byref(count), 1, 1, 0, 0, mpz)
    return int.from_bytes(bytes(data)[: count.value])


RSA_OID = {"1.2.840.113549.1.1.1": "rsaEncryption"}
RSA_PRIV_PARAM = {
    "rsaEncryption": PKParam(
        signature_size=256, oid="1.2.840.113549.1.1.1", pkcs1tag="RSA PRIVATE KEY"
    )
}
RSA_PUB_PARAM = {
    "rsaEncryption": PKParam(
        signature_size=256, oid="1.2.840.113549.1.1.1", pkcs1tag="RSA PUBLIC KEY"
    )
}


class RSAKeyPair(KeyPair):
    """The RSA algorithm."""

    random: Random
    public_key: RSAPubKey
    _key: _RSAPrivateKey
    _pub: _RSAPublicKey
    _alg = "rsaEncryption"
    _oids = RSA_OID
    _params = RSA_PRIV_PARAM

    def __init__(self, n_size: int, e_size: int, random: Random | None = None) -> None:
        self.random = random or Yarrow256()
        self._key = _RSAPrivateKey()
        self._pub = _RSAPublicKey()

        libhogweed.hogweed.nettle_rsa_private_key_init(ctypes.byref(self._key))
        libhogweed.hogweed.nettle_rsa_public_key_init(ctypes.byref(self._pub))

        if (
            libhogweed.hogweed.nettle_rsa_generate_keypair(
                ctypes.byref(self._pub),
                ctypes.byref(self._key),
                ctypes.byref(self.random._ctx),  # noqa: SLF001
                libnettle.nettle[f"{self.random._prefix}_random"],  # noqa: SLF001
                None,
                None,
                n_size,
                e_size,
            )
            == 0
        ):
            raise RSAError

        self.public_key = RSAPubKey(self.random)
        self.public_key._pub = self._pub  # noqa: SLF001

    def __del__(self) -> None:
        libhogweed.hogweed.nettle_rsa_private_key_clear(ctypes.byref(self._key))
        libhogweed.hogweed.nettle_rsa_public_key_clear(ctypes.byref(self._pub))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RSAKeyPair):
            return False
        return bytes(self) == bytes(other)

    def __hash__(self) -> int:
        return hash(bytes(self))

    @property
    def size(self) -> int:
        """Get key size."""
        return self._key.size

    def to_pkcs8(self) -> bytes:
        """Encapsulate key in PKCS #8 structure."""
        return PrivateKeyInfo(
            Integer(0),
            AlgorithmIdentifier(OID(self._params[self._alg].oid), Null()),
            OctetString(bytes(self)),
        ).to_der()

    def encrypt(self, msg: bytes) -> bytes:
        """Encrypt data."""
        return self.public_key.encrypt(msg)

    def decrypt(self, msg: bytes) -> bytes:
        """Decrypt data."""
        datalen = ctypes.c_size_t(256)
        data = ctypes.create_string_buffer(datalen.value)
        ciphertext = _MPZ_T()
        libgmp.gmp["__gmpz_init"](ctypes.byref(ciphertext))
        libgmp.gmp["__gmpz_import"](ctypes.byref(ciphertext), len(msg), 1, 1, 0, 0, msg)
        if (
            libhogweed.hogweed.nettle_rsa_decrypt(
                ctypes.byref(self._key), ctypes.byref(datalen), data, ciphertext
            )
            != 1
        ):
            raise RSAError
        libgmp.gmp["__gmpz_clear"](ctypes.byref(ciphertext))
        return bytes(data)[: datalen.value]

    def _oaep_decrypt(self, hashalg: str, msg: bytes, label: bytes) -> bytes:
        if libnettle.major < 3 or (libnettle.major == 3 and libnettle.minor < 10):
            raise NotImplementedError("OAEP first appeared in nettle 3.10")
        datalen = ctypes.c_size_t(256)
        data = ctypes.create_string_buffer(datalen.value)
        if (
            libhogweed.hogweed[f"nettle_rsa_oaep_{hashalg}_decrypt"](
                ctypes.byref(self._pub),
                ctypes.byref(self._key),
                ctypes.byref(self.random._ctx),  # noqa: SLF001
                libnettle.nettle[f"{self.random._prefix}_random"],  # noqa: SLF001
                len(label),
                label,
                ctypes.byref(datalen),
                data,
                msg,
            )
            != 1
        ):
            raise RSAError("Failed to decrypt data")
        return bytes(data)[: datalen.value]

    def oaep_sha256_decrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Decrypt a cipher text message using RSA with the OAEP padding scheme."""
        return self._oaep_decrypt("sha256", msg, label)

    def oaep_sha384_decrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Decrypt a cipher text message using RSA with the OAEP padding scheme."""
        return self._oaep_decrypt("sha384", msg, label)

    def oaep_sha512_decrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Decrypt a cipher text message using RSA with the OAEP padding scheme."""
        return self._oaep_decrypt("sha512", msg, label)

    def oaep_sha256_encrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Encrypt a clear text message using RSA with the OAEP padding scheme."""
        return self.public_key._oaep_encrypt("sha256", msg, label)  # noqa: SLF001

    def oaep_sha384_encrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Encrypt a clear text message using RSA with the OAEP padding scheme."""
        return self.public_key._oaep_encrypt("sha384", msg, label)  # noqa: SLF001

    def oaep_sha512_encrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Encrypt a clear text message using RSA with the OAEP padding scheme."""
        return self.public_key._oaep_encrypt("sha512", msg, label)  # noqa: SLF001

    def sign(self, hsh: SHA1 | SHA256 | SHA512) -> bytes:
        """Sign hash."""
        signature = _MPZ_T()
        libgmp.gmp["__gmpz_init"](ctypes.byref(signature))
        hname = hsh.__class__.__name__.lower()
        libhogweed.hogweed[f"nettle_rsa_{hname}_sign"](
            ctypes.byref(self._key),
            ctypes.byref(hsh._ctx),  # noqa: SLF001
            ctypes.byref(signature),
        )
        data = ctypes.create_string_buffer(256)
        count = ctypes.c_size_t()
        libgmp.gmp["__gmpz_export"](data, ctypes.byref(count), 1, 1, 0, 0, signature)
        libgmp.gmp["__gmpz_clear"](ctypes.byref(signature))
        return bytes(data)[: count.value]

    def verify(self, signature: bytes, hsh: SHA1 | SHA256 | SHA512) -> bool:
        """Verify signature."""
        return self.public_key.verify(signature, hsh)

    def __bytes__(self) -> bytes:
        return RSAPrivateKey(
            Integer(0),
            Integer(_mpz_to_int(self._pub.n)),
            Integer(_mpz_to_int(self._pub.e)),
            Integer(_mpz_to_int(self._key.d)),
            Integer(_mpz_to_int(self._key.p)),
            Integer(_mpz_to_int(self._key.q)),
            Integer(_mpz_to_int(self._key.a)),
            Integer(_mpz_to_int(self._key.b)),
            Integer(_mpz_to_int(self._key.c)),
        ).to_der()

    @classmethod
    def from_pkcs8(cls, data: bytes, random: Random | None = None) -> Self:
        """Deserialize PKCS #8 DER."""
        return cls._from_private_key_info(PrivateKeyInfo.from_der(data), random)

    @classmethod
    def _from_private_key_octet_string(
        cls,
        data: bytes,
        alg: str,  # noqa: ARG003
        random: Random | None = None,
    ) -> Self:
        """Deserialize RSA Private Key."""
        return cls._from_rsa_private_key(RSAPrivateKey.from_der(data), random)

    @classmethod
    def _from_rsa_private_key(
        cls, privkey: RSAPrivateKey, random: Random | None = None
    ) -> Self:
        if int(privkey.version) != 0:
            raise RSAError(f"Unknown RSAPrivateKey version: {int(privkey.version) + 1}")
        return cls.from_params(
            n=bytes(privkey.modulus),
            e=bytes(privkey.public_exponent),
            d=bytes(privkey.private_exponent),
            p=bytes(privkey.prime1),
            q=bytes(privkey.prime2),
            a=bytes(privkey.exponent1),
            b=bytes(privkey.exponent2),
            c=bytes(privkey.coefficient),
            random=random,
        )

    @classmethod
    def from_params(  # noqa: PLR0913
        cls,
        n: bytes,
        e: bytes,
        d: bytes,
        p: bytes,
        q: bytes,
        a: bytes,
        b: bytes,
        c: bytes,
        random: Random | None = None,
    ) -> Self:
        """Initialize keypair from params."""
        keypair = cls.__new__(cls)
        keypair.random = random
        keypair._key = _RSAPrivateKey()  # noqa: SLF001
        keypair._pub = _RSAPublicKey()  # noqa: SLF001
        libhogweed.hogweed.nettle_rsa_private_key_init(ctypes.byref(keypair._key))  # noqa: SLF001
        libhogweed.hogweed.nettle_rsa_public_key_init(ctypes.byref(keypair._pub))  # noqa: SLF001
        libgmp.gmp["__gmpz_import"](ctypes.byref(keypair._pub.n), len(n), 1, 1, 0, 0, n)  # noqa: SLF001
        libgmp.gmp["__gmpz_import"](ctypes.byref(keypair._pub.e), len(e), 1, 1, 0, 0, e)  # noqa: SLF001
        libgmp.gmp["__gmpz_import"](ctypes.byref(keypair._key.d), len(d), 1, 1, 0, 0, d)  # noqa: SLF001
        libgmp.gmp["__gmpz_import"](ctypes.byref(keypair._key.p), len(p), 1, 1, 0, 0, p)  # noqa: SLF001
        libgmp.gmp["__gmpz_import"](ctypes.byref(keypair._key.q), len(q), 1, 1, 0, 0, q)  # noqa: SLF001
        libgmp.gmp["__gmpz_import"](ctypes.byref(keypair._key.a), len(a), 1, 1, 0, 0, a)  # noqa: SLF001
        libgmp.gmp["__gmpz_import"](ctypes.byref(keypair._key.b), len(b), 1, 1, 0, 0, b)  # noqa: SLF001
        libgmp.gmp["__gmpz_import"](ctypes.byref(keypair._key.c), len(c), 1, 1, 0, 0, c)  # noqa: SLF001
        if (
            libhogweed.hogweed.nettle_rsa_public_key_prepare(ctypes.byref(keypair._pub))  # noqa: SLF001
            != 1
        ):
            raise RSAError
        if (
            libhogweed.hogweed.nettle_rsa_private_key_prepare(
                ctypes.byref(keypair._key)  # noqa: SLF001
            )
            != 1
        ):
            raise RSAError

        keypair.public_key = RSAPubKey(keypair.random)
        keypair.public_key._pub = keypair._pub  # noqa: SLF001
        return keypair


class RSAPubKey(PubKey):
    """A RSA Public Key."""

    random: Random
    _pub: _RSAPublicKey
    _alg = "rsaEncryption"
    _oids = RSA_OID
    _params = RSA_PUB_PARAM
    _hogweed = libhogweed.hogweed

    @property
    def size(self) -> int:
        """Get key size."""
        return self._pub.size

    def __init__(self, random: Random | None = None) -> None:
        self.random = random or Yarrow256()
        self._pub = _RSAPublicKey()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RSAPubKey):
            return False
        return bytes(self) == bytes(other)
        return all(
            [
                libgmp.gmp["__gmpz_cmp"](
                    ctypes.byref(self._pub.n), ctypes.byref(other._pub.n)
                )
                == 0,
                libgmp.gmp["__gmpz_cmp"](
                    ctypes.byref(self._pub.e), ctypes.byref(other._pub.e)
                )
                == 0,
            ]
        )

    def __hash__(self) -> int:
        return hash(bytes(self))

    def encrypt(self, msg: bytes) -> bytes:
        """Encrypt data."""
        ciphertext = _MPZ_T()
        libgmp.gmp["__gmpz_init"](ctypes.byref(ciphertext))
        if (
            libhogweed.hogweed.nettle_rsa_encrypt(
                ctypes.byref(self._pub),
                ctypes.byref(self.random._ctx),  # noqa: SLF001
                libnettle.nettle[f"{self.random._prefix}_random"],  # noqa: SLF001
                len(msg),
                msg,
                ciphertext,
            )
            != 1
        ):
            raise RSAError
        datalen = libgmp.gmp["__gmpz_sizeinbase"](ctypes.byref(ciphertext), 256)
        data = ctypes.create_string_buffer(datalen)
        count = ctypes.c_size_t()
        libgmp.gmp["__gmpz_export"](data, ctypes.byref(count), 1, 1, 0, 0, ciphertext)
        libgmp.gmp["__gmpz_clear"](ctypes.byref(ciphertext))
        return bytes(data)[: count.value]

    def verify(self, signature: bytes, hsh: SHA1 | SHA256 | SHA512) -> bool:
        """Verify signature."""
        sign = _MPZ_T()
        libgmp.gmp["__gmpz_init"](ctypes.byref(sign))
        libgmp.gmp["__gmpz_import"](
            ctypes.byref(sign), len(signature), 1, 1, 0, 0, signature
        )
        hname = hsh.__class__.__name__.lower()
        res = libhogweed.hogweed[f"nettle_rsa_{hname}_verify"](
            ctypes.byref(self._pub),
            ctypes.byref(hsh._ctx),  # noqa: SLF001
            ctypes.byref(sign),
        )
        libgmp.gmp["__gmpz_clear"](ctypes.byref(sign))
        return bool(res)

    def to_pkcs8(self) -> bytes:
        """Serialize key to pkcs8 DER."""
        return SubjectPublicKeyInfo(
            AlgorithmIdentifier(OID(self._params[self._alg].oid), Null()),
            BitString(bytes(self)),
        ).to_der()

    def __bytes__(self) -> bytes:
        return RSAPublicKey(
            Integer(_mpz_to_int(self._pub.n)),
            Integer(_mpz_to_int(self._pub.e)),
        ).to_der()

    def _oaep_encrypt(self, hashalg: str, msg: bytes, label: bytes) -> bytes:
        if libnettle.major < 3 or (libnettle.major == 3 and libnettle.minor < 10):
            raise NotImplementedError("OAEP first appeared in nettle 3.10")
        datalen = ctypes.c_size_t(self.size)
        data = ctypes.create_string_buffer(datalen.value)
        if (
            libhogweed.hogweed[f"nettle_rsa_oaep_{hashalg}_encrypt"](
                ctypes.byref(self._pub),
                ctypes.byref(self.random._ctx),  # noqa: SLF001
                libnettle.nettle[f"{self.random._prefix}_random"],  # noqa: SLF001
                len(label),
                label,
                len(msg),
                msg,
                data,
            )
            != 1
        ):
            raise RSAError("Failed to encrypt data")
        return bytes(data)

    def oaep_sha256_encrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Encrypt a clear text message using RSA with the OAEP padding scheme."""
        return self._oaep_encrypt("sha256", msg, label)

    def oaep_sha384_encrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Encrypt a clear text message using RSA with the OAEP padding scheme."""
        return self._oaep_encrypt("sha384", msg, label)

    def oaep_sha512_encrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Encrypt a clear text message using RSA with the OAEP padding scheme."""
        return self._oaep_encrypt("sha512", msg, label)

    @classmethod
    def _from_public_key_bit_string(
        cls,
        data: bytes,
        alg: str,  # noqa: ARG003
        random: Random | None = None,
    ) -> Self:
        """Deserialize pkcs1 DER."""
        return cls._from_rsa_public_key(RSAPublicKey.from_der(data), random)

    @classmethod
    def _from_rsa_public_key(
        cls, pubkey: RSAPublicKey, random: Random | None = None
    ) -> Self:
        """Deserialize pkcs1 DER."""
        n = int(pubkey.modulus)
        e = int(pubkey.public_exponent)
        return cls.from_params(
            n=n.to_bytes(n.bit_length() // 8 + 1),
            e=e.to_bytes(
                e.bit_length() // 8 + 1,
            ),
            random=random,
        )

    @classmethod
    def from_params(cls, n: bytes, e: bytes, random: Random | None = None) -> Self:
        """Initialize public key from params."""
        pubkey = cls.__new__(cls)
        pubkey._random = random  # noqa: SLF001
        pubkey._pub = _RSAPublicKey()  # noqa: SLF001
        libhogweed.hogweed.nettle_rsa_public_key_init(ctypes.byref(pubkey._pub))  # noqa: SLF001
        libgmp.gmp["__gmpz_import"](ctypes.byref(pubkey._pub.n), len(n), 1, 1, 0, 0, n)  # noqa: SLF001
        libgmp.gmp["__gmpz_import"](ctypes.byref(pubkey._pub.e), len(e), 1, 1, 0, 0, e)  # noqa: SLF001
        if (
            libhogweed.hogweed.nettle_rsa_public_key_prepare(ctypes.byref(pubkey._pub))  # noqa: SLF001
            != 1
        ):
            raise RSAError
        return pubkey
