#
# macs.py
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

"""Nettle mac functions."""

import ctypes

from . import hashes
from .exceptions import NotInitializedError
from .libnettle import libnettle


class _MACContext(ctypes.Structure):
    """Base class for MAC contexts."""


class MAC:
    """Base mac class."""

    #: Size of digest in bytes
    digest_size: int

    _ctx: _MACContext
    _ctxclass: type[_MACContext]
    _prefix: str
    _initialized: bool = False

    def __init__(self, key: bytes | None = None) -> None:
        self._ctx = self._ctxclass()
        if key is not None:
            self.set_key(key)

    def set_key(self, key: bytes) -> None:
        """Initialize MAC with key."""
        libnettle.nettle[f"{self._prefix}_set_key"](
            ctypes.byref(self._ctx), len(key), key
        )
        self._initialized = True

    def update(self, msg: bytes) -> None:
        """Process some more data."""
        self._check_initialized()
        libnettle.nettle[f"{self._prefix}_update"](
            ctypes.byref(self._ctx), len(msg), msg
        )

    def digest(self) -> bytes:
        """Extract the MAC and return it as bytes."""
        self._check_initialized()
        dgst = (ctypes.c_uint8 * self.digest_size)()
        if libnettle.major < 4:  # noqa: PLR2004
            libnettle.nettle[f"{self._prefix}_digest"](
                ctypes.byref(self._ctx), self.digest_size, dgst
            )
        else:
            libnettle.nettle[f"{self._prefix}_digest"](ctypes.byref(self._ctx), dgst)
        return bytes(dgst)

    def hexdigest(self) -> str:
        """Extract the MAC as hex string."""
        return self.digest().hex()

    def pbkdf2(self, iterations: int, salt: bytes, length: int) -> bytes:
        """Derive symmetric key from a password according to PKCS #5 PBKDF2."""
        self._check_initialized()
        key = (ctypes.c_uint8 * length)()
        libnettle.nettle.nettle_pbkdf2(
            ctypes.byref(self._ctx),
            libnettle.nettle[f"{self._prefix}_update"],
            libnettle.nettle[f"{self._prefix}_digest"],
            self.digest_size,
            iterations,
            len(salt),
            salt,
            length,
            key,
        )
        return bytes(key)

    def _check_initialized(self) -> None:
        if not self._initialized:
            raise NotInitializedError


class NonceMAC(MAC):
    """A MAC that uses a nonce."""

    def __init__(
        self, key: bytes | None = None, nonce: bytes | None = None
    ) -> None: ...
    def set_nonce(self, nonce: bytes) -> None:
        """Set nonce."""


class _SHA1Prefix(ctypes.Structure):
    _fields_ = [("state", ctypes.c_uint32 * 5), ("count", ctypes.c_uint64)]


class _HMACSHA1Ctx(_MACContext):
    _fields_ = [
        ("outer", _SHA1Prefix),
        ("inner", _SHA1Prefix),
        ("state", hashes._SHA1Ctx),  # noqa: SLF001
    ]


class _SHA256Prefix(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint32 * 8),
        ("count_low", ctypes.c_uint64),
        ("count_high", ctypes.c_uint64),
    ]


class _HMACSHA256Ctx(_MACContext):
    _fields_ = [
        ("outer", _SHA256Prefix),
        ("inner", _SHA256Prefix),
        ("state", hashes._SHA256Ctx),  # noqa: SLF001
    ]


class _SHA512Prefix(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint64 * 8),
        ("count_low", ctypes.c_uint64),
        ("count_high", ctypes.c_uint64),
    ]


class _HMACSHA512Ctx(_MACContext):
    _fields_ = [
        ("outer", _SHA512Prefix),
        ("inner", _SHA512Prefix),
        ("state", hashes._SHA512Ctx),  # noqa: SLF001
    ]


class HMAC_SHA1(MAC):  # noqa: N801
    """SHA1 based HMAC."""

    digest_size = hashes.SHA1.digest_size
    _prefix = "nettle_hmac_sha1"
    _ctxclass = _HMACSHA1Ctx


class HMAC_SHA256(MAC):  # noqa: N801
    """SHA256 based HMAC."""

    digest_size = hashes.SHA256.digest_size
    _prefix = "nettle_hmac_sha256"
    _ctxclass = _HMACSHA256Ctx


class HMAC_SHA512(MAC):  # noqa: N801
    """SHA512 based HMAC."""

    digest_size = hashes.SHA512.digest_size
    _prefix = "nettle_hmac_sha512"
    _ctxclass = _HMACSHA512Ctx
