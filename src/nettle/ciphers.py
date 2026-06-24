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
    NettleError,
    NonceLenError,
    NotInitializedError,
    ShortSeedError,
)
from .libnettle import libnettle


class Cipher:
    """Base cipher class."""

    key_size: int
    _ctx: ctypes.Array[ctypes.c_char]
    _ctx_size: int
    _prefix: str
    _encryption_key_uninitialized: bool
    _decryption_key_uninitialized: bool
    _nonce_uninitialized: bool | None

    def set_encrypt_key(self, key: bytes) -> None:
        """Set encrypt key to key."""
        if len(key) != self.key_size:
            raise KeyLenError
        libnettle.nettle[f"{self._prefix}_set_encrypt_key"](
            ctypes.byref(self._ctx), key
        )
        self._encryption_key_uninitialized = False

    def set_decrypt_key(self, key: bytes) -> None:
        """Set encrypt key to key."""
        if len(key) != self.key_size:
            raise KeyLenError
        if self._prefix == "nettle_camellia128":
            # Kludge since this is #defined in header file
            libnettle.nettle["nettle_camellia_set_decrypt_key"](
                ctypes.byref(self._ctx), key
            )
        else:
            libnettle.nettle[f"{self._prefix}_set_decrypt_key"](
                ctypes.byref(self._ctx), key
            )
        self._decryption_key_uninitialized = False

    def encrypt(self, msg: bytes) -> bytes:
        """Encrypt msg."""
        self._check_msg_len(msg)
        self._check_initialized_for_encryption()
        msglen = len(msg)
        dst = ctypes.create_string_buffer(msglen)
        libnettle.nettle[f"{self._prefix}_encrypt"](
            ctypes.byref(self._ctx), msglen, dst, msg
        )
        return bytes(dst)

    def decrypt(self, msg: bytes) -> bytes:
        """Decrypt msg."""
        self._check_msg_len(msg)
        self._check_initialized_for_decryption()
        msglen = len(msg)
        dst = ctypes.create_string_buffer(msglen)
        libnettle.nettle[f"{self._prefix}_decrypt"](
            ctypes.byref(self._ctx), msglen, dst, msg
        )
        return bytes(dst)

    def _check_msg_len(self, msg: bytes) -> None:
        """For non block ciphers: do nothing."""

    def _check_initialized_for_encryption(self) -> None:
        """Check if encryption key is initialized."""
        if self._encryption_key_uninitialized or self._nonce_uninitialized:
            raise NotInitializedError

    def _check_initialized_for_decryption(self) -> None:
        """Check if decryption key is initialized."""
        if self._decryption_key_uninitialized or self._nonce_uninitialized:
            raise NotInitializedError

    def _check_initialized_for_any(self) -> None:
        """Check if any key is initialized."""
        if (
            self._decryption_key_uninitialized and self._encryption_key_uninitialized
        ) or self._nonce_uninitialized:
            raise NotInitializedError


class SingleFuncCipher(Cipher):
    """A cipher with only one method for both encrypt and decrypt."""

    def crypt(self, msg: bytes) -> bytes:
        """Encrypt and decrypt."""
        self._check_msg_len(msg)
        self._check_initialized_for_any()
        msglen = len(msg)
        dst = ctypes.create_string_buffer(msglen)
        if self._prefix == "nettle_camellia192":
            # Kludge since this is #defined in header file
            libnettle.nettle["nettle_camellia256_crypt"](self._ctx, msglen, dst, msg)
        else:
            libnettle.nettle[f"{self._prefix}_crypt"](self._ctx, msglen, dst, msg)
        return bytes(dst)

    def encrypt(self, msg: bytes) -> bytes:
        """Encrypt msg."""
        return self.crypt(msg)

    def decrypt(self, msg: bytes) -> bytes:
        """Encrypt msg."""
        return self.crypt(msg)


class SingleKeyCipher(Cipher):
    """A cipher with only one key for both encrypt and decrypt."""

    min_key_size = 0
    max_key_size = 0
    key_size = 0

    def __init__(self, key: bytes | None = None) -> None:
        self._decryption_key_uninitialized = True
        self._encryption_key_uninitialized = True
        self._nonce_uninitialized = None
        if self.min_key_size == 0 and self.max_key_size == 0:
            self.min_key_size = self.max_key_size = self.key_size

        self._ctx = ctypes.create_string_buffer(self._ctx_size)
        if key is not None:
            self.set_key(key)

    def set_key(self, key: bytes) -> None:
        """Set key."""
        if not self.min_key_size <= len(key) <= self.max_key_size:
            raise KeyLenError
        if hasattr(self, "_set_key"):
            setter = f"{self._prefix}{self._set_key}"
        else:
            setter = f"{self._prefix}_set_key"
        if self.key_size == 0:
            libnettle.nettle[setter](ctypes.byref(self._ctx), len(key), key)
        else:
            libnettle.nettle[setter](ctypes.byref(self._ctx), key)
        self._decryption_key_uninitialized = False
        self._encryption_key_uninitialized = False


class DoubleKeyCipher(Cipher):
    """A cipher with separate keys for encrypt and decrypt."""

    def __init__(
        self, encrypt_key: bytes | None = None, decrypt_key: bytes | None = None
    ) -> None:
        self._decryption_key_uninitialized = True
        self._encryption_key_uninitialized = True
        self._nonce_uninitialized = None
        self._ctx = ctypes.create_string_buffer(self._ctx_size)
        if encrypt_key is not None:
            if len(encrypt_key) != self.key_size:
                raise KeyLenError
            self.set_encrypt_key(encrypt_key)

        if decrypt_key is not None:
            if len(decrypt_key) != self.key_size:
                raise KeyLenError
            self.set_decrypt_key(decrypt_key)


class NonceCipher(SingleKeyCipher):
    """A cipher that uses a nonce."""

    nonce_size = 0

    def __init__(self, key: bytes | None = None, nonce: bytes | None = None) -> None:
        self._decryption_key_uninitialized = True
        self._encryption_key_uninitialized = True
        self._nonce_uninitialized = True
        if self.min_key_size == 0 and self.max_key_size == 0:
            self.min_key_size = self.max_key_size = self.key_size

        self._ctx = ctypes.create_string_buffer(self._ctx_size)
        if key is not None:
            self.set_key(key)
        if nonce is not None:
            self.set_nonce(nonce)

    def set_nonce(self, nonce: bytes) -> None:
        """Set nonce."""
        if len(nonce) != self.nonce_size:
            raise NonceLenError
        libnettle.nettle[f"{self._prefix}_set_nonce"](ctypes.byref(self._ctx), nonce)
        self._nonce_uninitialized = False


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
        self._check_initialized_for_encryption()
        libnettle.nettle[f"{self._prefix}_invert_key"](
            ctypes.byref(self._ctx), ctypes.byref(self._ctx)
        )
        self._decryption_key_uninitialized = False
        self._encryption_key_uninitialized = False


class ParitySensitiveCipher(Cipher):
    """A cipher that is sensitive to parity."""

    _check_parity: str
    _fix_parity: str

    def check_parity(self, key: bytes) -> bool:
        """Check key parity."""
        if hasattr(self, "_check_parity"):
            func = self._check_parity
        else:
            func = f"{self._prefix}_check_parity"
        return libnettle.nettle[func](len(key), key) == 1

    def fix_parity(self, key: bytes) -> bytes:
        """Fix key parity."""
        fixed = ctypes.create_string_buffer(len(key))
        if hasattr(self, "_fix_parity"):
            func = self._fix_parity
        else:
            func = f"{self._prefix}_fix_parity"
        libnettle.nettle[func](len(key), fixed, key)
        return bytes(fixed)


class KeyWrapCipher(Cipher):
    """A cipher that can be used to wrap keys."""

    def keywrap(self, cleartext: bytes) -> bytes:
        """Wrap key."""
        self._check_initialized_for_encryption()
        if len(cleartext) % 8 != 0:
            raise DataLenError
        dstlen = len(cleartext) + 8
        dst = ctypes.create_string_buffer(dstlen)
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
        self._check_initialized_for_decryption()
        if len(ciphertext) % 8 != 0:
            raise DataLenError
        dstlen = len(ciphertext) - 8
        dst = ctypes.create_string_buffer(dstlen)
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


class AES128(AesFamilyCipher):
    """AES with 128 bit key size."""

    key_size = 16
    _ctx_size = 176
    _prefix = "nettle_aes128"


class AES192(AesFamilyCipher):
    """AES with 192 bit key size."""

    key_size = 24
    _ctx_size = 208
    _prefix = "nettle_aes192"


class AES256(AesFamilyCipher):
    """AES with 256 bit key size."""

    key_size = 32
    _ctx_size = 240
    _prefix = "nettle_aes256"


class Arcfour(SingleFuncCipher, SingleKeyCipher):
    """
    ARCFOUR is a historic stream cipher, also known under the trade marked name RC4.

    We do not recommend the use of ARCFOUR; the Nettle implementation
    is provided primarily for interoperability with existing
    applications and standards.

    """

    min_key_size = 1
    max_key_size = 256
    _ctx_size = 258
    _prefix = "nettle_arcfour"


class Arctwo(BlockCipher, SingleKeyCipher):
    """
    ARCTWO (also known as the trade marked name RC2) is a block cipher.

    We do not recommend the use of ARCTWO; the Nettle implementation
    is provided primarily for interoperability with existing
    applications and standards.

    """

    block_size = 8
    min_key_size = 1
    max_key_size = 128
    _ctx_size = 128
    _prefix = "nettle_arctwo"


class Blowfish(BlockCipher, SingleKeyCipher):
    """BLOWFISH is a block cipher designed by Bruce Schneier."""

    bcrypt_hash_size = 60
    bcrypt_binsalt_size = 16
    block_size = 8
    min_key_size = 8
    max_key_size = 56
    _ctx_size = 4168
    _prefix = "nettle_blowfish"

    @classmethod
    def bcrypt_hash(
        cls, key: str, scheme: str, log2rounds: int = -1, salt: bytes | None = None
    ) -> str:
        """Compute the bcrypt password hash."""
        if salt is not None and len(salt) != cls.bcrypt_binsalt_size:
            raise ShortSeedError
        dst = ctypes.create_string_buffer(cls.bcrypt_hash_size + 1)
        bkey = key.encode("utf-8")
        bscheme = scheme.encode("utf-8")
        if (
            libnettle.nettle.nettle_blowfish_bcrypt_hash(
                dst, len(bkey), bkey, len(bscheme), bscheme, log2rounds, salt
            )
            < 1
        ):
            raise NettleError
        return bytes(dst).decode()

    @classmethod
    def bcrypt_verify(cls, key: str, hashed: str) -> bool:
        """Verify the bcrypt password hash against the supplied plaintext password."""
        bkey = key.encode("utf-8")
        bhashed = hashed.encode("utf-8")
        return (
            libnettle.nettle.nettle_blowfish_bcrypt_verify(
                len(bkey), bkey, len(bhashed), bhashed
            )
            == 1
        )


class CamelliaFamilyCipher(
    DoubleKeyCipher, InvertibleKeyCipher, SingleFuncCipher, BlockCipher
):
    """
    Camellia is a block cipher developed by Mitsubishi and NTT.

    It is recommended by some Japanese and European authorities as an
    alternative to AES, and it is one of the selected algorithms in
    the New European Schemes for Signatures, Integrity and Encryption
    (NESSIE) project.

    """

    block_size: int = 16


class Camellia128(CamelliaFamilyCipher):
    """Camellia with 128 bit key size."""

    key_size = 16
    _ctx_size = 192
    _prefix = "nettle_camellia128"


class Camellia192(CamelliaFamilyCipher):
    """Camellia with 192 bit key size."""

    key_size = 24
    _ctx_size = 256
    _prefix = "nettle_camellia192"


class Camellia256(CamelliaFamilyCipher):
    """Camellia with 256 bit key size."""

    key_size = 32
    _ctx_size = 256
    _prefix = "nettle_camellia256"


class Cast128(BlockCipher, SingleKeyCipher):
    """CAST-128 is a block cipher, specified in RFC 2144."""

    block_size = 8
    key_size = 16
    _ctx_size = 84
    _prefix = "nettle_cast128"


class ChaCha(SingleFuncCipher, NonceCipher):
    """ChaCha is a variant of the stream cipher Salsa20."""

    block_size = 64
    counter_size = 8
    key_size = 32
    nonce_size = 8
    _ctx_size = 64
    _prefix = "nettle_chacha"

    def set_counter(self, counter: bytes) -> None:
        """Set the block counter."""
        if len(counter) != self.counter_size:
            raise NonceLenError
        libnettle.nettle[f"{self._prefix}_set_counter"](
            ctypes.byref(self._ctx), counter
        )

    def set_counter32(self, counter: bytes) -> None:
        """Set the block counter."""
        self.counter_size = 4
        self.nonce_size = 12
        if len(counter) != self.counter_size:
            raise NonceLenError
        libnettle.nettle[f"{self._prefix}_set_counter32"](
            ctypes.byref(self._ctx), counter
        )

    def set_nonce96(self, nonce: bytes) -> None:
        """Set a 96 bit nonce to be used with crypt32-method."""
        self.nonce_size = 12
        if len(nonce) != self.nonce_size:
            raise NonceLenError
        libnettle.nettle[f"{self._prefix}_set_nonce96"](ctypes.byref(self._ctx), nonce)
        self._nonce_uninitialized = False

    def crypt32(self, msg: bytes) -> bytes:
        """Encrypt and decrypt with a 96 bit nonce."""
        self._check_msg_len(msg)
        self._check_initialized_for_any()
        msglen = len(msg)
        dst = ctypes.create_string_buffer(msglen)
        libnettle.nettle[f"{self._prefix}_crypt32"](self._ctx, msglen, dst, msg)
        return bytes(dst)


class DES(BlockCipher, SingleKeyCipher, ParitySensitiveCipher):
    """
    DES is the old Data Encryption Standard, specified by NIST.

    The key size of DES is so small that keys can be found by brute
    force, using specialized hardware or lots of ordinary work
    stations in parallel. One shouldn't be using plain DES at all
    today, if one uses DES at all one should be using "triple DES",
    DES3.
    """

    block_size = 8
    key_size = 8
    _ctx_size = 128
    _prefix = "nettle_des"


class DES3(BlockCipher, SingleKeyCipher, ParitySensitiveCipher):
    """
    DES is the old Data Encryption Standard, specified by NIST.

    The key size of DES is so small that keys can be found by brute
    force, using specialized hardware or lots of ordinary work
    stations in parallel. One shouldn't be using plain DES at all
    today, if one uses DES at all one should be using "triple DES",
    DES3.
    """

    block_size = 8
    key_size = 24
    _ctx_size = 384
    _prefix = "nettle_des3"
    _check_parity = "nettle_des_check_parity"
    _fix_parity = "nettle_des_fix_parity"


class Salsa20_128(SingleFuncCipher, NonceCipher):  # noqa: N801
    """Salsa20 is a fairly recent stream cipher designed by D. J. Bernstein."""

    block_size = 64
    key_size = 16
    nonce_size = 8
    _ctx_size = 64
    _prefix = "nettle_salsa20"
    _set_key = "_128_set_key"


class Salsa20_256(SingleFuncCipher, NonceCipher):  # noqa: N801
    """Salsa20 is a fairly recent stream cipher designed by D. J. Bernstein."""

    block_size = 64
    key_size = 32
    nonce_size = 8
    _ctx_size = 64
    _prefix = "nettle_salsa20"
    _set_key = "_256_set_key"


class Serpent(BlockCipher, SingleKeyCipher):
    """SERPENT is one of the AES finalists."""

    block_size = 16
    min_key_size = 16
    max_key_size = 32
    _ctx_size = 528
    _prefix = "nettle_serpent"


class SM4(BlockCipher, DoubleKeyCipher, SingleFuncCipher):
    """SM4 is a block cipher standard adopted by the government of the PRC."""

    block_size = 16
    key_size = 16
    _ctx_size = 128
    _prefix = "nettle_sm4"

    def __init__(
        self, encrypt_key: bytes | None = None, decrypt_key: bytes | None = None
    ) -> None:
        if libnettle.major < 3 or (libnettle.major == 3 and libnettle.minor < 10):
            raise NotImplementedError("SM4 first appeared in nettle 3.9")
        super().__init__(encrypt_key, decrypt_key)


class Twofish(BlockCipher, SingleKeyCipher):
    """Another AES finalist, this one designed by Bruce Schneier and others."""

    block_size = 16
    min_key_size = 16
    max_key_size = 32
    _ctx_size = 4256
    _prefix = "nettle_twofish"
