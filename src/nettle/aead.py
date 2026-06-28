"""Authenticated Encryption with Associated Data."""

import ctypes

from .ciphers import BlockCipher
from .libnettle import libnettle


class AEAD:
    """Authenticated encryption with associated data."""

    digest_size = 16
    block_size = 16
    cipher: BlockCipher
    _ctx: ctypes.Array[ctypes.c_char]
    _key: ctypes.Array[ctypes.c_char]
    _prefix: str

    def __init__(self, cipher: BlockCipher, iv: bytes) -> None: ...

    def update(self, msg: bytes) -> None:
        """Process associated data for authentication."""
        libnettle.nettle[f"{self._prefix}_update"](
            ctypes.byref(self._ctx), ctypes.byref(self._key), len(msg), msg
        )

    def digest(self) -> bytes:
        """Generate a digest of digest_size bytes."""
        dgst = ctypes.create_string_buffer(self.digest_size)
        func = libnettle.nettle[f"{self.cipher._prefix}_encrypt"]  # noqa: SLF001
        if libnettle.major < 4:
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
        self.cipher._check_initialized_for_encryption()  # noqa: SLF001

        func = libnettle.nettle[f"{self.cipher._prefix}_encrypt"]  # noqa: SLF001
        size = len(cleartext)
        dst = ctypes.create_string_buffer(size)

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
        self.cipher._check_initialized_for_encryption()  # noqa: SLF001
        func = libnettle.nettle[f"{self.cipher._prefix}_encrypt"]  # noqa: SLF001
        size = len(ciphertext)
        dst = ctypes.create_string_buffer(size)
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


class EAX(AEAD):
    """The EAX mode is an AEAD mode which combines CTR mode encryption."""

    digest_size = 16
    block_size = 16
    _ctx_size = 64
    _prefix = "nettle_eax"

    def __init__(self, cipher: BlockCipher, nonce: bytes) -> None:
        cipher._check_initialized_for_encryption()  # noqa: SLF001

        self.cipher = cipher
        self._key_size = cipher.key_size
        self._ctx = ctypes.create_string_buffer(self._ctx_size)

        func = libnettle.nettle[f"{self.cipher._prefix}_encrypt"]  # noqa: SLF001

        self._key = ctypes.create_string_buffer(self._key_size)
        libnettle.nettle[f"{self._prefix}_set_key"](
            ctypes.byref(self._key),
            ctypes.byref(self.cipher._ctx),
            func,
        )

        self.set_nonce(nonce)

        libnettle.nettle[f"{self._prefix}_encrypt"].argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        libnettle.nettle[f"{self._prefix}_digest"].argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
        ]

    def set_nonce(self, nonce: bytes) -> None:
        """Initialize using the given nonce."""
        libnettle.nettle[f"{self._prefix}_set_nonce"].argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        libnettle.nettle[f"{self._prefix}_set_nonce"](
            ctypes.byref(self._ctx),
            ctypes.byref(self._key),
            ctypes.byref(self.cipher._ctx),
            libnettle.nettle[f"{self.cipher._prefix}_encrypt"],  # noqa: SLF001
            len(nonce),
            nonce,
        )


class GCM(AEAD):
    """Galois Counter Mode."""

    _ctx_size = 64
    _key_size = 2048
    _prefix = "nettle_gcm"

    def __init__(self, cipher: BlockCipher, iv: bytes) -> None:
        cipher._check_initialized_for_encryption()  # noqa: SLF001

        self.cipher = cipher

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

    def set_iv(self, iv: bytes) -> None:
        """Initialize using the given IV."""
        libnettle.nettle[f"{self._prefix}_set_iv"](
            ctypes.byref(self._ctx), ctypes.byref(self._key), len(iv), iv
        )
