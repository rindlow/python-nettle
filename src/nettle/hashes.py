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


class _HashContext(ctypes.Structure):
    """Base hash context class."""

    def initialize(self) -> None:
        """Call initalizer."""


class Hash:
    """Base hash class."""

    _ctxclass: type[_HashContext]
    _ctx: _HashContext
    _prefix: str

    def __init__(self, data: bytes = b"") -> None:
        """If data is given, it is used to update hash."""
        self._ctx = self._ctxclass()
        self._ctx.initialize()

        if (datalen := len(data)) > 0:
            libnettle.nettle[f"{self._prefix}_update"](
                ctypes.byref(self._ctx), datalen, data
            )

    def copy(self) -> Self:
        """Return a copy of self."""
        newctx = self._ctxclass()
        ctypes.pointer(newctx)[0] = self._ctx
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
        if libnettle.major < 4:  # noqa: PLR2004
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


class _SHA1Ctx(_HashContext):
    _fields_ = [
        ("state", ctypes.c_uint32 * 5),
        ("count", ctypes.c_uint64),
        ("index", ctypes.c_uint),
        ("block", ctypes.c_uint8 * 64),
    ]

    def initialize(self) -> None:
        libnettle.nettle.nettle_sha1_init(ctypes.byref(self))


class SHA1(DigestableHash):
    """
    SHA1 is a hash function specified by NIST.

    It outputs hash values of 160 bits, or 20 octets.
    """

    digest_size = 20
    _ctxclass = _SHA1Ctx
    _prefix = "nettle_sha1"


# SHA-2


class _SHA256Ctx(_HashContext):
    _fields_ = [
        ("state", ctypes.c_uint32 * 8),
        ("count", ctypes.c_uint64),
        ("index", ctypes.c_uint),
        ("block", ctypes.c_uint8 * 64),
    ]

    def initialize(self) -> None:
        libnettle.nettle.nettle_sha256_init(ctypes.byref(self))


class SHA256(DigestableHash):
    """
    SHA256 is a member of the SHA2 family.

    It outputs hash values of 256 bits, or 32 octets.
    """

    digest_size = 32
    _ctxclass = _SHA256Ctx
    _prefix = "nettle_sha256"


class _SHA512Ctx(_HashContext):
    _fields_ = [
        ("state", ctypes.c_uint64 * 8),
        ("count_low", ctypes.c_uint64),
        ("count_high", ctypes.c_uint64),
        ("index", ctypes.c_uint),
        ("block", ctypes.c_uint8 * 128),
    ]

    def initialize(self) -> None:
        libnettle.nettle.nettle_sha512_init(ctypes.byref(self))


class SHA512(DigestableHash):
    """
    SHA512 is a larger sibling to SHA256.

    The internal variables are 64 bits rather than 32, making it
    significantly slower on 32-bit computers. It outputs hash values
    of 512 bits, or 64 octets.
    """

    digest_size = 64
    _ctxclass = _SHA512Ctx
    _prefix = "nettle_sha512"


# SHA-3


class _SHA3state(ctypes.Structure):
    _fields_ = [("a", ctypes.c_uint64 * 25)]


class _NettleBlock8(ctypes.Union):
    _fields_ = [("b", ctypes.c_uint8 * 8), ("u64", ctypes.c_uint64)]  # noqa: RUF012


# Unified context for nettle >= 4
class _SHA3Ctx(_HashContext):
    _fields_ = [
        ("sha3_state", _SHA3state),
        ("index", ctypes.c_uint),
        ("shake_flag", ctypes.c_int),
        ("block", _NettleBlock8),
    ]

    def initialize(self) -> None:
        libnettle.nettle.nettle_sha3_init(ctypes.byref(self))


# Separate contexts for nettle < 4
class _SHA3_128Ctx(_HashContext):  # noqa: N801
    _fields_ = [
        ("sha3_state", _SHA3state),
        ("index", ctypes.c_uint),
        ("block", ctypes.c_uint8 * 168),
    ]

    def initialize(self) -> None:
        libnettle.nettle.nettle_sha3_128_init(ctypes.byref(self))


class _SHA3_224Ctx(_HashContext):  # noqa: N801
    _fields_ = [
        ("sha3_state", _SHA3state),
        ("index", ctypes.c_uint),
        ("block", ctypes.c_uint8 * 144),
    ]

    def initialize(self) -> None:
        libnettle.nettle.nettle_sha3_224_init(ctypes.byref(self))


class _SHA3_256Ctx(_HashContext):  # noqa: N801
    _fields_ = [
        ("sha3_state", _SHA3state),
        ("index", ctypes.c_uint),
        ("block", ctypes.c_uint8 * 136),
    ]

    def initialize(self) -> None:
        libnettle.nettle.nettle_sha3_256_init(ctypes.byref(self))


class _SHA3_384Ctx(_HashContext):  # noqa: N801
    _fields_ = [
        ("sha3_state", _SHA3state),
        ("index", ctypes.c_uint),
        ("block", ctypes.c_uint8 * 104),
    ]

    def initialize(self) -> None:
        libnettle.nettle.nettle_sha3_384_init(ctypes.byref(self))


class _SHA3_512Ctx(_HashContext):  # noqa: N801
    _fields_ = [
        ("sha3_state", _SHA3state),
        ("index", ctypes.c_uint),
        ("block", ctypes.c_uint8 * 72),
    ]

    def initialize(self) -> None:
        libnettle.nettle.nettle_sha3_512_init(ctypes.byref(self))


class SHA3_128(ShakeableHash):  # noqa: N801
    """
    Nettle also supports a SHA-3 extendable-output function (XOF) called SHAKE.

    This is SHA3 with 128-bit output size.
    """

    _ctxclass: type[_HashContext] = _SHA3Ctx
    _prefix = "nettle_sha3_128"

    def __init__(self, data: bytes = b"") -> None:
        if libnettle.major < 4:  # noqa: PLR2004
            self._ctxclass = _SHA3_128Ctx
        super().__init__(data)


class SHA3_224(DigestableHash):  # noqa: N801
    """
    The SHA3 hash functions were specified by NIST in response to weaknesses in SHA1.

    This is SHA3 with 224-bit output size.
    """

    digest_size = 28
    _ctxclass: type[_HashContext] = _SHA3Ctx if libnettle.major >= 4 else _SHA3_224Ctx  # noqa: PLR2004
    _prefix = "nettle_sha3_224"


class SHA3_256(DigestableHash, ShakeableHash):  # noqa: N801
    """
    The SHA3 hash functions were specified by NIST in response to weaknesses in SHA1.

    This is SHA3 with 256-bit output size.
    """

    digest_size = 32
    _ctxclass: type[_HashContext] = _SHA3Ctx if libnettle.major >= 4 else _SHA3_256Ctx  # noqa: PLR2004
    _prefix = "nettle_sha3_256"
