"""Nettle cipher functions."""

import ctypes

from .libnettle import libnettle


class AuthenticationError(Exception):
    """Wrapped key is not authenticated.."""


class DataLenError(Exception):
    """Data length not multiple of block size."""


class KeyLenError(Exception):
    """Key not of expected length."""


class NotInitializedError(Exception):
    """Cipher not initialized."""


class Cipher:
    """Base cipher protocol."""

    key_size: int
    _ctx: ctypes.Structure
    _ctxclass: type[ctypes.Structure]
    _prefix: str
    _initialized: int = 0
    _required: int = 1

    def set_encrypt_key(self, key: bytes) -> None:
        """Set encrypt key to key."""
        if len(key) != self.key_size:
            raise KeyLenError
        ctxp = ctypes.pointer(self._ctx)
        libnettle.nettle[f"{self._prefix}_set_encrypt_key"](ctxp, key)
        self._initialized += 1

    def set_decrypt_key(self, key: bytes) -> None:
        """Set encrypt key to key."""
        if len(key) != self.key_size:
            raise KeyLenError
        ctxp = ctypes.pointer(self._ctx)
        libnettle.nettle[f"{self._prefix}_set_decrypt_key"](ctxp, key)
        self._initialized += 1

    def encrypt(self, msg: bytes) -> bytes:
        """Encrypt msg."""
        self._check_msg_len(msg)
        self.check_initialized()
        msglen = len(msg)
        dst = (ctypes.c_uint8 * msglen)()
        libnettle.nettle[f"{self._prefix}_encrypt"](self._ctx, msglen, dst, msg)
        return bytes(dst)

    def decrypt(self, msg: bytes) -> bytes:
        """Decrypt msg."""
        self._check_msg_len(msg)
        self.check_initialized()
        msglen = len(msg)
        dst = (ctypes.c_uint8 * msglen)()
        libnettle.nettle[f"{self._prefix}_decrypt"](self._ctx, msglen, dst, msg)
        return bytes(dst)

    def _check_msg_len(self, msg: bytes) -> None:
        """For non block ciphers: do nothing."""

    def check_initialized(self) -> None:
        """Check if all keys are initialized."""
        if self._initialized < self._required:
            raise NotInitializedError


class SingleFuncCipher(Cipher):
    """A cipher with only one method for both encrypt and decrypt."""

    def crypt(self, msg: bytes) -> bytes:
        """Encrypt and decrypt."""
        self._check_msg_len(msg)
        if self._initialized < self._required:
            raise NotInitializedError
        msglen = len(msg)
        dst = (ctypes.c_uint8 * msglen)()
        libnettle.nettle[f"{self._prefix}_crypt"](self._ctx, msglen, dst, msg)
        return bytes(dst)


class SingleKeyCipher(Cipher):
    """A cipher with only one key for both encrypt and decrypt."""

    def set_key(self, key: bytes) -> None:
        """Set key."""
        ctxp = ctypes.pointer(self._ctx)
        libnettle.nettle[f"{self._prefix}_set_key"](ctxp, key)
        self._initialized += 1


class DoubleKeyCipher(Cipher):
    """A cipher with separate keys for encrypt and decrypt."""


class NonceCipher(Cipher):
    """A cipher that uses a nonce."""

    _initialized = 2

    def set_nonce(self, nonce: bytes) -> None:
        """Set nonce."""
        ctxp = ctypes.pointer(self._ctx)
        libnettle.nettle[f"{self._prefix}_set_nonce"](ctxp, nonce)
        self._initialized += 1


class BlockCipher(Cipher):
    """A block cipher."""

    block_size: int

    def _check_msg_len(self, msg: bytes) -> None:
        if len(msg) % self.block_size != 0:
            raise DataLenError


class InvertibleKeyCipher(Cipher):
    """A cipher that can invert the key."""

    def invert_key(self) -> None:
        """Invert key."""
        if self._initialized < self._required:
            raise NotInitializedError
        ctxp = ctypes.pointer(self._ctx)
        libnettle.nettle[f"{self._prefix}_invert_key"](ctxp, ctxp)


class ParitySensitiveCipher(Cipher):
    """A cipher that is sensitive to parity."""

    def check_parity(self, key: bytes) -> bool:
        """Check key parity."""
        return libnettle.nettle[f"{self._prefix}_check_parity"](key)

    def fix_parity(self, key: bytes) -> bytes:
        """Fix key parity."""
        return libnettle.nettle[f"{self._prefix}_check_parity"](key)


class KeyWrapCipher(Cipher):
    """A cipher that can be used to wrap keys."""

    def keywrap(self, cleartext: bytes) -> bytes:
        """Wrap key."""
        if self._initialized < self._required:
            raise NotInitializedError
        if len(cleartext) % 8 != 0:
            raise DataLenError
        dstlen = len(cleartext) + 8
        dst = (ctypes.c_uint8 * dstlen)()
        libnettle.nettle.nettle_nist_keywrap16(
            self._ctx,
            libnettle.nettle[f"{self._prefix}_encrypt"],
            b"\xa6" * 8,
            dstlen,
            dst,
            cleartext,
        )
        return bytes(dst)

    def keyunwrap(self, ciphertext: bytes) -> bytes:
        """Unwrap key."""
        if self._initialized < self._required:
            raise NotInitializedError
        if len(ciphertext) % 8 != 0:
            raise DataLenError
        dstlen = len(ciphertext) - 8
        dst = (ctypes.c_uint8 * dstlen)()
        if libnettle.nettle.nettle_nist_keyunwrap16(
            self._ctx,
            libnettle.nettle[f"{self._prefix}_decrypt"],
            b"\xa6" * 8,
            dstlen,
            dst,
            ciphertext,
        ):
            return bytes(dst)
        raise AuthenticationError


class AesFamilyCipher(DoubleKeyCipher, InvertibleKeyCipher, KeyWrapCipher, BlockCipher):
    """AES is a block cipher specified by NIST as a replacement for the DES standard."""

    block_size: int = 16

    def __init__(
        self, encrypt_key: bytes | None = None, decrypt_key: bytes | None = None
    ) -> None:
        self._ctx = self._ctxclass()

        if encrypt_key is not None:
            if len(encrypt_key) != self.key_size:
                raise KeyLenError
            self.set_encrypt_key(encrypt_key)
            self._is_initialized = True

        if decrypt_key is not None:
            if len(decrypt_key) != self.key_size:
                raise KeyLenError
            self.set_decrypt_key(decrypt_key)
            self._is_initialized = True


class _AES128ctx(ctypes.Structure):
    _fields_ = [("keys", ctypes.c_uint32 * 4 * 11)]


class _AES192ctx(ctypes.Structure):
    _fields_ = [("keys", ctypes.c_uint32 * 4 * 13)]


class _AES256ctx(ctypes.Structure):
    _fields_ = [("keys", ctypes.c_uint32 * 4 * 15)]


class AES128(AesFamilyCipher):
    """AES with 128 bit key sie."""

    key_size = 16
    _ctxclass = _AES128ctx
    _prefix = "nettle_aes128"


class AES192(AesFamilyCipher):
    """AES with 192 bit key sie."""

    key_size = 24
    _ctxclass = _AES192ctx
    _prefix = "nettle_aes192"


class AES256(AesFamilyCipher):
    """AES with 256 bit key sie."""

    key_size = 32
    _ctxclass = _AES256ctx
    _prefix = "nettle_aes256"


## Cipher modes


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
            ctx, func, bsize, iv, size, dst, cleartext
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
            ctx, func, bsize, iv, size, dst, ciphertext
        )
        return bytes(dst)


class AEADCipherMode(CipherMode):
    def update(self, msg: bytes) -> None:
        """Process associated data for authentication."""


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
