"""Nettle hash functions."""

import ctypes
from typing import Protocol, Self

from .libnettle import libnettle


class _Initializible(Protocol):
    def initialize(self) -> None: ...


class Hash:
    """Base hash class."""

    _ctxclass: type[_Initializible]
    _ctx: ctypes.Structure
    _prefix: str

    def __init__(self, msg: bytes = b"") -> None:
        """If msg is given, it is used to update hash."""
        self._ctx = self._ctxclass()
        self._ctx.initialize()
        ctxp = ctypes.pointer(self._ctx)

        if (msglen := len(msg)) > 0:
            libnettle.nettle[f"{self._prefix}_update"](ctxp, msglen, msg)

    def copy(self) -> Self:
        """Return a copy of self."""
        newctx = self._ctxclass()
        ctypes.pointer(newctx)[0] = self._ctx
        newhash = self.__class__()
        newhash._ctx = newctx  # noqa: SLF001
        return newhash

    def update(self, msg: bytes = b"") -> None:
        """Update hash with msg."""
        ctxp = ctypes.pointer(self._ctx)
        if (msglen := len(msg)) > 0:
            libnettle.nettle[f"{self._prefix}_update"](ctxp, msglen, msg)


class DigestableHash(Hash):
    """A hash that can produce digests."""

    digest_size: int

    def digest(self: DigestableHash) -> bytes:
        """Generate a digest of digest_size bytes."""
        dgst = (ctypes.c_uint8 * self.digest_size)()
        ctxp = ctypes.pointer(self._ctx)
        dgstp = ctypes.pointer(dgst)
        libnettle.nettle[f"{self._prefix}_digest"](ctxp, dgstp)
        return bytes(dgst)

    def hexdigest(self: DigestableHash) -> str:
        """Generate a hex digest of digest_size bytes."""
        return self.digest().hex()


class ShakeableHash(Hash):
    """A hash that can generate shake."""

    def shake(self: ShakeableHash, length: int) -> bytes:
        """Generate a shake of length bytes. Also reset the context."""
        dgst = (ctypes.c_uint8 * length)()
        ctxp = ctypes.pointer(self._ctx)
        dgstp = ctypes.pointer(dgst)
        libnettle.nettle[f"{self._prefix}_shake"](ctxp, length, dgstp)
        return bytes(dgst)

    def shake_output(self: ShakeableHash, length: int) -> bytes:
        """Generate a shake of length bytes. Does not reset the context."""
        dgst = (ctypes.c_uint8 * length)()
        ctxp = ctypes.pointer(self._ctx)
        dgstp = ctypes.pointer(dgst)
        libnettle.nettle[f"{self._prefix}_shake_output"](ctxp, length, dgstp)
        return bytes(dgst)


## SHA-2


class _SHA256ctx(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint32 * 8),
        ("count", ctypes.c_uint64),
        ("index", ctypes.c_uint32),
        ("block", ctypes.c_uint8 * 64),
    ]

    def initialize(self) -> None:
        libnettle.nettle.nettle_sha256_init(ctypes.pointer(self))


class SHA256(DigestableHash):
    """
    SHA256 is a member of the SHA2 family.

    It outputs hash values of 256 bits, or 32 octets.
    """

    digest_size = 32
    _ctxclass = _SHA256ctx
    _prefix = "nettle_sha256"


class _SHA512ctx(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint64 * 8),
        ("count_low", ctypes.c_uint64),
        ("count_high", ctypes.c_uint64),
        ("index", ctypes.c_uint32),
        ("block", ctypes.c_uint8 * 128),
    ]

    def initialize(self) -> None:
        libnettle.nettle.nettle_sha512_init(ctypes.pointer(self))


class SHA512(DigestableHash):
    """
    SHA512 is a larger sibling to SHA256.

    The internal variables are 64 bits rather than 32, making it
    significantly slower on 32-bit computers. It outputs hash values
    of 512 bits, or 64 octets.
    """

    digest_size = 64
    _ctxclass = _SHA512ctx
    _prefix = "nettle_sha512"


## SHA-3


class _SHA3state(ctypes.Structure):
    _fields_ = [("a", ctypes.c_uint64 * 25)]


class _NettleBlock8(ctypes.Union):
    _fields_ = [("b", ctypes.c_uint8 * 8), ("u64", ctypes.c_uint64)]  # noqa: RUF012


class _SHA3ctx(ctypes.Structure):
    _fields_ = [
        ("sha3_state", _SHA3state),
        ("index", ctypes.c_uint32),
        ("shake_flag", ctypes.c_int),
        ("block", _NettleBlock8),
    ]

    def initialize(self) -> None:
        libnettle.nettle.nettle_sha3_init(ctypes.pointer(self))


class SHA3_128(ShakeableHash):  # noqa: N801
    """
    Nettle also supports a SHA-3 extendable-output function (XOF) called SHAKE.

    This is SHA3 with 128-bit output size.
    """

    _ctxclass = _SHA3ctx
    _prefix = "nettle_sha3_128"


class SHA3_224(DigestableHash):  # noqa: N801
    """
    The SHA3 hash functions were specified by NIST in response to weaknesses in SHA1.

    This is SHA3 with 224-bit output size.
    """

    digest_size = 28
    _ctxclass = _SHA3ctx
    _prefix = "nettle_sha3_224"


class SHA3_256(DigestableHash, ShakeableHash):  # noqa: N801
    """
    The SHA3 hash functions were specified by NIST in response to weaknesses in SHA1.

    This is SHA3 with 256-bit output size.
    """

    digest_size = 32
    _ctxclass = _SHA3ctx
    _prefix = "nettle_sha3_256"
