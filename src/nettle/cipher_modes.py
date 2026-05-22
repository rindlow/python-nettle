"""Cipher modes."""

import ctypes
import typing

from .libnettle import libnettle

if typing.TYPE_CHECKING:
    from .ciphers import BlockCipher


class CipherMode:
    """Cipher modes specifies the procedure to use when encrypting a large message."""

    _prefix: str
    cipher: BlockCipher
    iv: bytes

    def encrypt(self, cleartext: bytes) -> bytes:
        """Encrypt cleartext."""
        self.cipher.check_initialized()
        ctx = self.cipher._ctx  # noqa: SLF001
        func = libnettle.nettle[f"{self.cipher._prefix}_encrypt"]  # noqa: SLF001
        bsize = self.cipher.block_size
        iv = (ctypes.c_ubyte * bsize)(*(int(c) for c in self.iv))
        size = len(cleartext)
        dst = (ctypes.c_uint8 * size)()
        libnettle.nettle[f"{self._prefix}_encrypt"](
            ctypes.byref(ctx), func, bsize, iv, size, dst, cleartext
        )
        return bytes(dst)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext."""
        self.cipher.check_initialized()
        ctx = self.cipher._ctx  # noqa: SLF001
        func = libnettle.nettle[f"{self.cipher._prefix}_decrypt"]  # noqa: SLF001
        bsize = self.cipher.block_size
        iv = (ctypes.c_ubyte * bsize)(*(int(c) for c in self.iv))
        size = len(ciphertext)
        dst = (ctypes.c_uint8 * size)()
        libnettle.nettle[f"{self._prefix}_decrypt"](
            ctypes.byref(ctx), func, bsize, iv, size, dst, ciphertext
        )
        return bytes(dst)


class CBC(CipherMode):
    """
    Cipher Block Chaining.

    When using CBC mode, plaintext blocks are not encrypted
    independently of each other, like in Electronic Cook Book mode.
    Instead, when encrypting a block in CBC mode, the previous
    ciphertext block is XORed with the plaintext before it is fed to
    the block cipher. When encrypting the first block, a random block
    called an IV, or Initialization Vector, is used as the “previous
    ciphertext block”. The IV should be chosen randomly, but it need
    not be kept secret, and can even be transmitted in the clear
    together with the encrypted data.

    """

    _prefix = "nettle_cbc"

    def __init__(self, cipher: BlockCipher, iv: bytes) -> None:
        self.cipher = cipher
        self.iv = iv
