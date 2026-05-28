#
# hash.py
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

"""Nettle hash functions."""

import ctypes
from typing import Self

from .libnettle import libnettle

V4 = 4


class Hash:
    """Base hash class."""

    _ctx_size: int
    _ctx: ctypes.Array[ctypes.c_char]
    _prefix: str
    _init_func: str

    def __init__(self, data: bytes = b"") -> None:
        """If data is given, it is used to update hash."""
        self._ctx = ctypes.create_string_buffer(self._ctx_size)
        libnettle.nettle[self._init_func](ctypes.byref(self._ctx))

        if (datalen := len(data)) > 0:
            libnettle.nettle[f"{self._prefix}_update"](
                ctypes.byref(self._ctx), datalen, data
            )

    def _ctx_init(self) -> None:
        pass

    def copy(self) -> Self:
        """Return a copy of self."""
        newctx = ctypes.create_string_buffer(bytes(self._ctx), self._ctx_size)
        newhash = self.__class__()
        newhash._ctx = newctx  # noqa: SLF001
        return newhash

    def update(self, data: bytes = b"") -> None:
        """Update hash with data."""
        if (datalen := len(data)) > 0:
            libnettle.nettle[f"{self._prefix}_update"](
                ctypes.byref(self._ctx), datalen, data
            )


class DigestableHash(Hash):
    """A hash that can produce digests."""

    #: Size of digest in bytes
    digest_size: int

    def digest(self) -> bytes:
        """Generate a digest of digest_size bytes."""
        dgst = (ctypes.c_uint8 * self.digest_size)()
        if libnettle.major < V4:
            libnettle.nettle[f"{self._prefix}_digest"](
                ctypes.byref(self._ctx), self.digest_size, dgst
            )
        else:
            libnettle.nettle[f"{self._prefix}_digest"](ctypes.byref(self._ctx), dgst)
        return bytes(dgst)

    def hexdigest(self) -> str:
        """Generate a hex digest of digest_size bytes."""
        return self.digest().hex()


class ShakeableHash(Hash):
    """A hash that can generate shake."""

    def shake(self, length: int) -> bytes:
        """Generate a shake of length bytes. Also reset the context."""
        dgst = (ctypes.c_uint8 * length)()
        libnettle.nettle[f"{self._prefix}_shake"](ctypes.byref(self._ctx), length, dgst)
        return bytes(dgst)

    def shake_output(self, length: int) -> bytes:
        """Generate a shake of length bytes. Does not reset the context."""
        dgst = (ctypes.c_uint8 * length)()
        libnettle.nettle[f"{self._prefix}_shake_output"](
            ctypes.byref(self._ctx), length, dgst
        )
        return bytes(dgst)


# SHA-1


class SHA1(DigestableHash):
    """
    SHA1 is a hash function specified by NIST.

    It outputs hash values of 160 bits, or 20 octets.
    """

    digest_size = 20
    _ctx_size = 104
    _prefix = "nettle_sha1"
    _init_func = "nettle_sha1_init"


# SHA-2


class SHA256(DigestableHash):
    """
    SHA256 is a member of the SHA2 family.

    It outputs hash values of 256 bits, or 32 octets.
    """

    digest_size = 32
    _ctx_size = 112
    _prefix = "nettle_sha256"
    _init_func = "nettle_sha256_init"


class SHA512(DigestableHash):
    """
    SHA512 is a larger sibling to SHA256.

    The internal variables are 64 bits rather than 32, making it
    significantly slower on 32-bit computers. It outputs hash values
    of 512 bits, or 64 octets.
    """

    digest_size = 64
    _ctx_size = 216
    _prefix = "nettle_sha512"
    _init_func = "nettle_sha512_init"


# SHA-3


class SHA3_128(ShakeableHash):  # noqa: N801
    """
    Nettle also supports a SHA-3 extendable-output function (XOF) called SHAKE.

    This is SHA3 with 128-bit output size.
    """

    _ctx_size = 376 if libnettle.major < V4 else 216
    _prefix = "nettle_sha3_128"
    _init_func = "nettle_sha3_128_init" if libnettle.major < V4 else "nettle_sha3_init"


class SHA3_224(DigestableHash):  # noqa: N801
    """
    The SHA3 hash functions were specified by NIST in response to weaknesses in SHA1.

    This is SHA3 with 224-bit output size.
    """

    digest_size = 28
    _ctx_size = 352 if libnettle.major < V4 else 216
    _prefix = "nettle_sha3_224"
    _init_func = "nettle_sha3_224_init" if libnettle.major < V4 else "nettle_sha3_init"


class SHA3_256(DigestableHash, ShakeableHash):  # noqa: N801
    """
    The SHA3 hash functions were specified by NIST in response to weaknesses in SHA1.

    This is SHA3 with 256-bit output size.
    """

    digest_size = 32
    _ctx_size = 344 if libnettle.major < V4 else 216
    _prefix = "nettle_sha3_256"
    _init_func = "nettle_sha3_256_init" if libnettle.major < V4 else "nettle_sha3_init"
