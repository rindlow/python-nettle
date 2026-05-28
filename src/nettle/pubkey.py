#
# pubkey.py
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

"""Nettle public key ciphers."""

import ctypes

from .exceptions import RSAError
from .hashes import SHA1, SHA256, SHA512
from .libgmp import libgmp
from .libhogweed import libhogweed
from .libnettle import libnettle
from .randomness import Yarrow256


# _MPZ_T = ctypes.c_char * 16


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


class RSAKeyPair:
    """The RSA algorithm."""

    public_key: "RSAPubKey"
    yarrow: Yarrow256
    _key: _RSAPrivateKey
    _pub: _RSAPublicKey

    def __init__(self, yarrow: Yarrow256 | None = None) -> None:
        if yarrow is None:
            self.yarrow = Yarrow256()
        else:
            self.yarrow = yarrow
        self._key = _RSAPrivateKey()
        self._pub = _RSAPublicKey()

        libhogweed.hogweed.nettle_rsa_private_key_init(ctypes.byref(self._key))
        libhogweed.hogweed.nettle_rsa_public_key_init(ctypes.byref(self._pub))

        self.public_key = RSAPubKey(self.yarrow)
        self.public_key._pub = self._pub  # noqa: SLF001

    def __del__(self) -> None:
        """Deallocate memory upon destruction."""
        libhogweed.hogweed.nettle_rsa_private_key_clear(ctypes.byref(self._key))
        libhogweed.hogweed.nettle_rsa_public_key_clear(ctypes.byref(self._pub))

    @property
    def size(self) -> int:
        """Get key size."""
        return self._key.size

    def from_params(  # noqa: PLR0913
        self,
        n: bytes,
        e: bytes,
        d: bytes,
        p: bytes,
        q: bytes,
        a: bytes,
        b: bytes,
        c: bytes,
    ) -> None:
        """Initialize keypair from params."""
        print(type(self._pub), type(self._pub.n))

        libgmp.gmp["__gmpz_import"](ctypes.byref(self._pub.n), len(n), 1, 1, 0, 0, n)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._pub.e), len(e), 1, 1, 0, 0, e)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._key.d), len(d), 1, 1, 0, 0, d)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._key.p), len(p), 1, 1, 0, 0, p)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._key.q), len(q), 1, 1, 0, 0, q)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._key.a), len(a), 1, 1, 0, 0, a)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._key.b), len(b), 1, 1, 0, 0, b)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._key.c), len(c), 1, 1, 0, 0, c)
        if (
            libhogweed.hogweed.nettle_rsa_public_key_prepare(ctypes.byref(self._pub))
            != 1
        ):
            raise RSAError
        if (
            libhogweed.hogweed.nettle_rsa_private_key_prepare(ctypes.byref(self._key))
            != 1
        ):
            raise RSAError

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

    # def oaep_sha256_decrypt(self, msg: bytes, label: bytes | None = None) -> bytes: ...
    # def oaep_sha256_encrypt(self, msg: bytes, label: bytes | None = None) -> bytes: ...
    # def oaep_sha384_decrypt(self, msg: bytes, label: bytes | None = None) -> bytes: ...
    # def oaep_sha384_encrypt(self, msg: bytes, label: bytes | None = None) -> bytes: ...
    # def oaep_sha512_decrypt(self, msg: bytes, label: bytes | None = None) -> bytes: ...
    # def oaep_sha512_encrypt(self, msg: bytes, label: bytes | None = None) -> bytes: ...
    # def from_pkcs1(self, buffer: bytes) -> None: ...
    # def from_pkcs8(self, buffer: bytes) -> None: ...

    def genkey(self, n_size: int, e_size: int) -> None:
        """Generate a new RSA keypair."""
        if (
            libhogweed.hogweed.nettle_rsa_generate_keypair(
                ctypes.byref(self._pub),
                ctypes.byref(self._key),
                ctypes.byref(self.yarrow._ctx),  # noqa: SLF001
                libnettle.nettle.nettle_yarrow256_random,
                None,
                None,
                n_size,
                e_size,
            )
            == 0
        ):
            raise RSAError

    #     def read_key(self, filename: str) -> None: ...
    #     def read_pkcs1_key(self, key: bytes) -> None: ...
    #     def read_pkcs8_key(self, key: bytes) -> None: ...

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

    # def to_pkcs1_key(self) -> bytes: ...

    def verify(self, signature: bytes, hsh: SHA1 | SHA256 | SHA512) -> bool:
        """Verify signature."""
        return self.public_key.verify(signature, hsh)

    def write_key(self, filename: str) -> None: ...


class RSAPubKey:
    """A RSA Public Key."""

    yarrow: Yarrow256
    _pub: _RSAPublicKey

    @property
    def size(self) -> int:
        """Get key size."""
        return self._pub.size

    def __init__(self, yarrow: Yarrow256 | None = None) -> None:
        self.yarrow = yarrow or Yarrow256()

    def encrypt(self, msg: bytes) -> bytes:
        """Encrypt data."""
        ciphertext = _MPZ_T()
        libgmp.gmp["__gmpz_init"](ctypes.byref(ciphertext))
        if (
            libhogweed.hogweed.nettle_rsa_encrypt(
                ctypes.byref(self._pub),
                ctypes.byref(self.yarrow._ctx),  # noqa: SLF001
                libnettle.nettle.nettle_yarrow256_random,
                len(msg),
                msg,
                ciphertext,
            )
            != 1
        ):
            raise RSAError
        datalen = libgmp.gmp["__gmpz_sizeinbase"](ctypes.byref(ciphertext), 256)
        data = (ctypes.c_byte * datalen)()
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

    def oaep_sha256_encrypt(self, msg: bytes, label: bytes | None = None) -> bytes: ...
    def oaep_sha384_encrypt(self, msg: bytes, label: bytes | None = None) -> bytes: ...
    def oaep_sha512_encrypt(self, msg: bytes, label: bytes | None = None) -> bytes: ...
    def from_cert(self, cert: bytes) -> None: ...
    def from_pkcs1(self, key: bytes) -> None: ...
    def from_pkcs8(self, key: bytes) -> None: ...
    def from_params(self, n: bytes, e: bytes) -> None: ...
    def to_pkcs8_key(self) -> bytes: ...
    def read_key(self, filename: str) -> None: ...
    def write_key(self, filename: str) -> None: ...
