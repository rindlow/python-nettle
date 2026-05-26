#
# cipher.py
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

"""Nettle cipher functions."""

import ctypes

from .exceptions import (
    AuthenticationError,
    DataLenError,
    KeyLenError,
    NotInitializedError,
)
from .libnettle import libnettle


class Cipher:
    """Base cipher class."""

    key_size: int
    _ctx: ctypes.Array[ctypes.c_char]
    _ctx_size: int
    _prefix: str
    _initialized: int = 0
    _required: int = 1

    def set_encrypt_key(self, key: bytes) -> None:
        """Set encrypt key to key."""
        if len(key) != self.key_size:
            raise KeyLenError
        libnettle.nettle[f"{self._prefix}_set_encrypt_key"](
            ctypes.byref(self._ctx), key
        )
        self._initialized += 1

    def set_decrypt_key(self, key: bytes) -> None:
        """Set encrypt key to key."""
        if len(key) != self.key_size:
            raise KeyLenError
        libnettle.nettle[f"{self._prefix}_set_decrypt_key"](
            ctypes.byref(self._ctx), key
        )
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
        libnettle.nettle[f"{self._prefix}_set_key"](ctypes.byref(self._ctx), key)
        self._initialized += 1


class DoubleKeyCipher(Cipher):
    """A cipher with separate keys for encrypt and decrypt."""


class NonceCipher(Cipher):
    """A cipher that uses a nonce."""

    _initialized = 2

    def set_nonce(self, nonce: bytes) -> None:
        """Set nonce."""
        libnettle.nettle[f"{self._prefix}_set_nonce"](ctypes.byref(self._ctx), nonce)
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
        libnettle.nettle[f"{self._prefix}_invert_key"](
            ctypes.byref(self._ctx), ctypes.byref(self._ctx)
        )


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
        self._ctx = ctypes.create_string_buffer(self._ctx_size)
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


class AES128(AesFamilyCipher):
    """AES with 128 bit key sie."""

    key_size = 16
    _ctx_size = 176
    _prefix = "nettle_aes128"


class AES192(AesFamilyCipher):
    """AES with 192 bit key sie."""

    key_size = 24
    _ctx_size = 208
    _prefix = "nettle_aes192"


class AES256(AesFamilyCipher):
    """AES with 256 bit key sie."""

    key_size = 32
    _ctx_size = 240
    _prefix = "nettle_aes256"
