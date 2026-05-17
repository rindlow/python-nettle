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


class _CipherContext(ctypes.Structure):
    """Base class for cipher contexts."""


class Cipher:
    """Base cipher protocol."""

    key_size: int
    _ctx: _CipherContext
    _ctxclass: type[_CipherContext]
    _prefix: str
    _initialized: int = 0
    _required: int = 1

    def set_encrypt_key(self, key: bytes) -> None:
        """Set encrypt key to key."""
        if len(key) != self.key_size:
            raise KeyLenError
        ctxp = ctypes.byref(self._ctx)
        libnettle.nettle[f"{self._prefix}_set_encrypt_key"](ctxp, key)
        self._initialized += 1

    def set_decrypt_key(self, key: bytes) -> None:
        """Set encrypt key to key."""
        if len(key) != self.key_size:
            raise KeyLenError
        ctxp = ctypes.byref(self._ctx)
        libnettle.nettle[f"{self._prefix}_set_decrypt_key"](ctxp, key)
        self._initialized += 1

    def encrypt(self, msg: bytes) -> bytes:
        """Encrypt msg."""
        self._check_msg_len(msg)
        self.check_initialized()
        msglen = len(msg)
        dst = (ctypes.c_uint8 * msglen)()
        libnettle.nettle[f"{self._prefix}_encrypt"](
            ctypes.byref(self._ctx), msglen, dst, msg
        )
        return bytes(dst)

    def decrypt(self, msg: bytes) -> bytes:
        """Decrypt msg."""
        self._check_msg_len(msg)
        self.check_initialized()
        msglen = len(msg)
        dst = (ctypes.c_uint8 * msglen)()
        libnettle.nettle[f"{self._prefix}_decrypt"](
            ctypes.byref(self._ctx), msglen, dst, msg
        )
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
        ctxp = ctypes.byref(self._ctx)
        libnettle.nettle[f"{self._prefix}_set_key"](ctxp, key)
        self._initialized += 1


class DoubleKeyCipher(Cipher):
    """A cipher with separate keys for encrypt and decrypt."""


class NonceCipher(Cipher):
    """A cipher that uses a nonce."""

    _initialized = 2

    def set_nonce(self, nonce: bytes) -> None:
        """Set nonce."""
        ctxp = ctypes.byref(self._ctx)
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
        ctxp = ctypes.byref(self._ctx)
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
            ctypes.byref(self._ctx),
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
            ctypes.byref(self._ctx),
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
            self._initialized += 1

        if decrypt_key is not None:
            if len(decrypt_key) != self.key_size:
                raise KeyLenError
            self.set_decrypt_key(decrypt_key)
            self._initialized += 1


class _AES128ctx(_CipherContext):
    _fields_ = [("keys", ctypes.c_uint32 * 4 * 11)]


class _AES192ctx(_CipherContext):
    _fields_ = [("keys", ctypes.c_uint32 * 4 * 13)]


class _AES256ctx(_CipherContext):
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


class _AEADContext(ctypes.Structure):
    """Base class for AEAD contexts."""


class _AEADKey(ctypes.Structure):
    """Base class for AEAD keys."""


class AEADCipherMode(CipherMode):
    """Authenticated encryption with associated data."""

    _ctx: _AEADContext
    _key: _AEADKey
    digest_size = 16
    block_size = 16

    def update(self, msg: bytes) -> None:
        """Process associated data for authentication."""
        ctxp = ctypes.byref(self._ctx)
        libnettle.nettle[f"{self._prefix}_update"](
            ctxp, ctypes.byref(self._key), len(msg), msg
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


class _NettleBlock16(ctypes.Union):
    _align_ = 16
    _fields_ = [("b", ctypes.c_uint8 * 16), ("u64", ctypes.c_uint64 * 2)]  # noqa: RUF012


class _GCMCtx(_AEADContext):
    _fields_ = [
        ("iv", _NettleBlock16),
        ("ctr", _NettleBlock16),
        ("x", _NettleBlock16),
        ("auth_size", ctypes.c_uint64),
        ("data_size", ctypes.c_uint64),
    ]


class _GCMKey(_AEADKey):
    _fields_ = [("h", _NettleBlock16 * 0x80)]


class GCM(AEADCipherMode):
    """Galois Counter Mode."""

    _prefix = "nettle_gcm"

    def __init__(self, cipher: BlockCipher, iv: bytes) -> None:
        cipher.check_initialized()

        self.cipher = cipher
        self.iv = iv

        ctx = cipher._ctx  # noqa: SLF001
        func = libnettle.nettle[f"{self.cipher._prefix}_encrypt"]  # noqa: SLF001

        self._key = _GCMKey()
        libnettle.nettle[f"{self._prefix}_set_key"](
            ctypes.byref(self._key), ctypes.byref(ctx), func
        )

        self._ctx = _GCMCtx()
        libnettle.nettle[f"{self._prefix}_set_iv"](
            ctypes.byref(self._ctx), ctypes.byref(self._key), len(iv), iv
        )
