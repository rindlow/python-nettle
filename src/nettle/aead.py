"""Authenticated Encryption with Associated Data."""

import ctypes

from .ciphers import BlockCipher
from .libnettle import libnettle


class AEAD:
    """Authenticated encryption with associated data."""

    digest_size = 16
    block_size = 16
    cipher: BlockCipher
    iv: bytes
    _ctx: ctypes.Array[ctypes.c_char]
    _key: ctypes.Array[ctypes.c_char]
    _prefix: str

    def update(self, msg: bytes) -> None:
        """Process associated data for authentication."""
        libnettle.nettle[f"{self._prefix}_update"](
            ctypes.byref(self._ctx), ctypes.byref(self._key), len(msg), msg
        )

    def digest(self) -> bytes:
        """Generate a digest of digest_size bytes."""
        dgst = (ctypes.c_uint8 * self.digest_size)()
        func = libnettle.nettle[f"{self.cipher._prefix}_encrypt"]  # noqa: SLF001
        if libnettle.major < 4:  # noqa: PLR2004
            libnettle.nettle[f"{self._prefix}_digest"](
                ctypes.byref(self._ctx),
                ctypes.byref(self._key),
                ctypes.byref(self.cipher._ctx),  # noqa: SLF001
                func,
                self.digest_size,
                dgst,
            )
        else:
            libnettle.nettle[f"{self._prefix}_digest"](
                ctypes.byref(self._ctx),
                ctypes.byref(self._key),
                ctypes.byref(self.cipher._ctx),  # noqa: SLF001
                func,
                dgst,
            )
        return bytes(dgst)

    def hexdigest(self) -> str:
        """Generate a hex digest of digest_size bytes."""
        return self.digest().hex()

    def encrypt(self, cleartext: bytes) -> bytes:
        """Encrypt cleartext."""
        self.cipher.check_initialized()

        func = libnettle.nettle[f"{self.cipher._prefix}_encrypt"]  # noqa: SLF001
        size = len(cleartext)
        dst = (ctypes.c_uint8 * size)()

        libnettle.nettle[f"{self._prefix}_encrypt"](
            ctypes.byref(self._ctx),
            ctypes.byref(self._key),
            ctypes.byref(self.cipher._ctx),  # noqa: SLF001
            func,
            size,
            dst,
            cleartext,
        )
        return bytes(dst)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext."""
        self.cipher.check_initialized()
        func = libnettle.nettle[f"{self.cipher._prefix}_encrypt"]  # noqa: SLF001
        size = len(ciphertext)
        dst = (ctypes.c_uint8 * size)()
        libnettle.nettle[f"{self._prefix}_decrypt"](
            ctypes.byref(self._ctx),
            ctypes.byref(self._key),
            ctypes.byref(self.cipher._ctx),  # noqa: SLF001
            func,
            size,
            dst,
            ciphertext,
        )
        return bytes(dst)


class _NettleBlock16(ctypes.Union):
    _align_ = 16
    _fields_ = [("b", ctypes.c_uint8 * 16), ("u64", ctypes.c_uint64 * 2)]  # noqa: RUF012


class GCM(AEAD):
    """Galois Counter Mode."""

    _ctx_size = 64
    _key_size = 2048
    _prefix = "nettle_gcm"

    def __init__(self, cipher: BlockCipher, iv: bytes) -> None:
        cipher.check_initialized()

        self.cipher = cipher
        self.iv = iv

        ctx = cipher._ctx  # noqa: SLF001
        func = libnettle.nettle[f"{self.cipher._prefix}_encrypt"]  # noqa: SLF001

        self._key = ctypes.create_string_buffer(self._key_size)
        libnettle.nettle[f"{self._prefix}_set_key"](
            ctypes.byref(self._key), ctypes.byref(ctx), func
        )

        self._ctx = ctypes.create_string_buffer(self._ctx_size)
        libnettle.nettle[f"{self._prefix}_set_iv"](
            ctypes.byref(self._ctx), ctypes.byref(self._key), len(iv), iv
        )
