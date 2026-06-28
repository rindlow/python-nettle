"""Cipher modes."""

import ctypes

from .ciphers import BlockCipher
from .exceptions import DataLenError
from .libnettle import libnettle


class CipherMode:
    """Cipher modes specifies the procedure to use when encrypting a large message."""

    cipher: BlockCipher
    iv: bytes
    _prefix: str
    _decrypt_cipher_func: str

    def __init__(self, cipher: BlockCipher, iv: bytes) -> None:
        self.cipher = cipher
        self.iv = iv

    def encrypt(self, cleartext: bytes) -> bytes:
        """Encrypt cleartext."""
        self.cipher._check_initialized_for_encryption()  # noqa: SLF001
        ctx = self.cipher._ctx  # noqa: SLF001
        func = libnettle.nettle[f"{self.cipher._prefix}_encrypt"]  # noqa: SLF001
        bsize = self.cipher.block_size
        iv = (ctypes.c_ubyte * bsize)(*(int(c) for c in self.iv))
        size = len(cleartext)
        dst = ctypes.create_string_buffer(size)
        libnettle.nettle[f"{self._prefix}_encrypt"](
            ctypes.byref(ctx), func, bsize, iv, size, dst, cleartext
        )
        return bytes(dst)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext."""
        if self._decrypt_cipher_func == "_encrypt":
            self.cipher._check_initialized_for_encryption()  # noqa: SLF001
        else:
            self.cipher._check_initialized_for_decryption()  # noqa: SLF001
        ctx = self.cipher._ctx  # noqa: SLF001
        func = libnettle.nettle[f"{self.cipher._prefix}{self._decrypt_cipher_func}"]  # noqa: SLF001
        bsize = self.cipher.block_size
        iv = (ctypes.c_ubyte * bsize)(*(int(c) for c in self.iv))
        size = len(ciphertext)
        dst = ctypes.create_string_buffer(size)
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
    _decrypt_cipher_func = "_decrypt"


class CTR(CipherMode):
    """
    Counter Mode.

    Counter mode (CTR) uses the block cipher as a keyed pseudo-random
    generator. The output of the generator is XORed with the data to
    be encrypted. It can be understood as a way to transform a block
    cipher to a stream cipher.
    """

    _prefix = "nettle_ctr"

    def __init__(self, cipher: BlockCipher, ctr: bytes) -> None:
        self.cipher = cipher
        self.iv = ctr

    def encrypt(self, cleartext: bytes) -> bytes:
        """Encrypt cleartext."""
        return self.crypt(cleartext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt cleartext."""
        return self.crypt(ciphertext)

    def crypt(self, cleartext: bytes) -> bytes:
        """Crypt cleartext."""
        self.cipher._check_initialized_for_encryption()  # noqa: SLF001
        ctx = self.cipher._ctx  # noqa: SLF001
        func = libnettle.nettle[f"{self.cipher._prefix}_encrypt"]  # noqa: SLF001
        bsize = self.cipher.block_size
        iv = (ctypes.c_ubyte * bsize)(*(int(c) for c in self.iv))
        size = len(cleartext)
        dst = ctypes.create_string_buffer(size)
        libnettle.nettle[f"{self._prefix}_crypt"](
            ctypes.byref(ctx), func, bsize, iv, size, dst, cleartext
        )
        return bytes(dst)


class CFB(CipherMode):
    """Cipher Feedback mode borrow some characteristics from stream ciphers."""

    _prefix = "nettle_cfb"
    _decrypt_cipher_func = "_encrypt"


class CFB8(CipherMode):
    """Cipher Feedback 8-bit mode borrow some characteristics from stream ciphers."""

    _prefix = "nettle_cfb8"
    _decrypt_cipher_func = "_encrypt"


class XTS(CipherMode):
    """XEX-based tweaked-codebook mode with ciphertext stealing (XTS)."""

    _tweak_cipher: BlockCipher

    def __init__(self, cipher: BlockCipher, tweak_key: bytes) -> None:
        self.cipher = cipher
        self._tweak_cipher = type(cipher)()
        self._tweak_cipher.set_encrypt_key(tweak_key)

    def encrypt(self, cleartext: bytes) -> bytes:
        """Not implemented, use encrypt_message instead."""
        raise NotImplementedError

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Not implemented, use decrypt_message instead."""
        raise NotImplementedError

    def encrypt_message(self, cleartext: bytes, tweak: bytes) -> bytes:
        """Encrypt cleartext."""
        self.cipher._check_initialized_for_encryption()  # noqa: SLF001
        self._tweak_cipher._check_initialized_for_encryption()  # noqa: SLF001
        size = len(cleartext)
        if size < self.cipher.block_size:
            raise DataLenError
        dst = ctypes.create_string_buffer(size)
        libnettle.nettle.nettle_xts_encrypt_message(
            ctypes.byref(self.cipher._ctx),  # noqa: SLF001
            ctypes.byref(self._tweak_cipher._ctx),  # noqa: SLF001
            libnettle.nettle[f"{self.cipher._prefix}_encrypt"],  # noqa: SLF001
            tweak,
            size,
            dst,
            cleartext,
        )
        return bytes(dst)

    def decrypt_message(self, ciphertext: bytes, tweak: bytes) -> bytes:
        """Encrypt cleartext."""
        self.cipher._check_initialized_for_encryption()  # noqa: SLF001
        self._tweak_cipher._check_initialized_for_encryption()  # noqa: SLF001
        size = len(ciphertext)
        if size < self.cipher.block_size:
            raise DataLenError
        dst = ctypes.create_string_buffer(size)
        libnettle.nettle.nettle_xts_decrypt_message(
            ctypes.byref(self.cipher._ctx),  # noqa: SLF001
            ctypes.byref(self._tweak_cipher._ctx),  # noqa: SLF001
            libnettle.nettle[f"{self.cipher._prefix}_decrypt"],  # noqa: SLF001
            libnettle.nettle[f"{self.cipher._prefix}_encrypt"],  # noqa: SLF001
            tweak,
            size,
            dst,
            ciphertext,
        )
        return bytes(dst)
