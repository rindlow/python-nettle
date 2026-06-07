#
# pubkey.py
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

"""Nettle public key ciphers."""

from __future__ import annotations

import base64
import ctypes
import pathlib
import re
from typing import TYPE_CHECKING

from .asn1 import (
    OID,
    ASN1Error,
    BitString,
    Integer,
    Null,
    OctetString,
)
from .asn1types import (
    AlgorithmIdentifier,
    Certificate,
    PrivateKeyInfo,
    RSAPrivateKey,
    RSAPublicKey,
    SubjectPublicKeyInfo,
)
from .exceptions import KeyLenError, ParseError, RSAError
from .libgmp import libgmp
from .libhogweed import libhogweed
from .libnettle import libnettle
from .randomness import Random, Yarrow256

if TYPE_CHECKING:
    from .hashes import SHA1, SHA256, SHA512

RSAENCRYPTION = "1.2.840.113549.1.1.1"


class _MPZStruct(ctypes.Structure):
    _fields_ = [
        ("_mp_alloc", ctypes.c_int),
        ("_mp_size", ctypes.c_int),
        ("_mp_d", ctypes.c_void_p),
    ]


_MPZ_T = _MPZStruct * 1


def _mpz_to_int(mpz: ctypes.Array[_MPZStruct]) -> int:
    datalen = libgmp.gmp["__gmpz_sizeinbase"](ctypes.byref(mpz), 256)
    data = ctypes.create_string_buffer(datalen)
    count = ctypes.c_size_t()
    libgmp.gmp["__gmpz_export"](data, ctypes.byref(count), 1, 1, 0, 0, mpz)
    return int.from_bytes(bytes(data)[: count.value])


class _RSAPrivateKey(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_size_t),
        ("d", _MPZ_T),
        ("p", _MPZ_T),
        ("q", _MPZ_T),
        ("a", _MPZ_T),
        ("b", _MPZ_T),
        ("c", _MPZ_T),
    ]


class _RSAPublicKey(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_size_t),
        ("n", _MPZStruct * 1),
        ("e", _MPZ_T),
    ]


class PublicKey:
    """Base class for Public Keys."""


class KeyPair:
    """Base class for Key Pairs."""

    public_key: PublicKey
    random: Random


class RSAKeyPair(KeyPair):
    """The RSA algorithm."""

    public_key: RSAPubKey
    _key: _RSAPrivateKey
    _pub: _RSAPublicKey

    def __init__(self, random: Random | None = None) -> None:
        self.random = random or Yarrow256()
        self._key = _RSAPrivateKey()
        self._pub = _RSAPublicKey()

        libhogweed.hogweed.nettle_rsa_private_key_init(ctypes.byref(self._key))
        libhogweed.hogweed.nettle_rsa_public_key_init(ctypes.byref(self._pub))

        self.public_key = RSAPubKey(self.random)
        self.public_key._pub = self._pub  # noqa: SLF001

    def __del__(self) -> None:
        libhogweed.hogweed.nettle_rsa_private_key_clear(ctypes.byref(self._key))
        libhogweed.hogweed.nettle_rsa_public_key_clear(ctypes.byref(self._pub))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RSAKeyPair):
            return False
        return all(
            [
                libgmp.gmp["__gmpz_cmp"](
                    ctypes.byref(self._pub.n), ctypes.byref(other._pub.n)
                )
                == 0,
                libgmp.gmp["__gmpz_cmp"](
                    ctypes.byref(self._pub.e), ctypes.byref(other._pub.e)
                )
                == 0,
                libgmp.gmp["__gmpz_cmp"](
                    ctypes.byref(self._key.d), ctypes.byref(other._key.d)
                )
                == 0,
                libgmp.gmp["__gmpz_cmp"](
                    ctypes.byref(self._key.p), ctypes.byref(other._key.p)
                )
                == 0,
                libgmp.gmp["__gmpz_cmp"](
                    ctypes.byref(self._key.q), ctypes.byref(other._key.q)
                )
                == 0,
                libgmp.gmp["__gmpz_cmp"](
                    ctypes.byref(self._key.a), ctypes.byref(other._key.a)
                )
                == 0,
                libgmp.gmp["__gmpz_cmp"](
                    ctypes.byref(self._key.b), ctypes.byref(other._key.b)
                )
                == 0,
                libgmp.gmp["__gmpz_cmp"](
                    ctypes.byref(self._key.c), ctypes.byref(other._key.c)
                )
                == 0,
            ]
        )

    def __hash__(self) -> int:
        return hash(self._key) + hash(self._pub)

    @property
    def size(self) -> int:
        """Get key size."""
        return self._key.size

    def from_params(  # noqa: PLR0913
        self,
        n: bytes,
        e: bytes,
        d: bytes,
        p: bytes,
        q: bytes,
        a: bytes,
        b: bytes,
        c: bytes,
    ) -> None:
        """Initialize keypair from params."""
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._pub.n), len(n), 1, 1, 0, 0, n)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._pub.e), len(e), 1, 1, 0, 0, e)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._key.d), len(d), 1, 1, 0, 0, d)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._key.p), len(p), 1, 1, 0, 0, p)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._key.q), len(q), 1, 1, 0, 0, q)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._key.a), len(a), 1, 1, 0, 0, a)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._key.b), len(b), 1, 1, 0, 0, b)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._key.c), len(c), 1, 1, 0, 0, c)
        if (
            libhogweed.hogweed.nettle_rsa_public_key_prepare(ctypes.byref(self._pub))
            != 1
        ):
            raise RSAError
        if (
            libhogweed.hogweed.nettle_rsa_private_key_prepare(ctypes.byref(self._key))
            != 1
        ):
            raise RSAError

    def encrypt(self, msg: bytes) -> bytes:
        """Encrypt data."""
        return self.public_key.encrypt(msg)

    def decrypt(self, msg: bytes) -> bytes:
        """Decrypt data."""
        datalen = ctypes.c_size_t(256)
        data = ctypes.create_string_buffer(datalen.value)
        ciphertext = _MPZ_T()
        libgmp.gmp["__gmpz_init"](ctypes.byref(ciphertext))
        libgmp.gmp["__gmpz_import"](ctypes.byref(ciphertext), len(msg), 1, 1, 0, 0, msg)
        if (
            libhogweed.hogweed.nettle_rsa_decrypt(
                ctypes.byref(self._key), ctypes.byref(datalen), data, ciphertext
            )
            != 1
        ):
            raise RSAError
        libgmp.gmp["__gmpz_clear"](ctypes.byref(ciphertext))
        return bytes(data)[: datalen.value]

    def _oaep_decrypt(self, hashalg: str, msg: bytes, label: bytes) -> bytes:
        datalen = ctypes.c_size_t(256)
        data = ctypes.create_string_buffer(datalen.value)
        if (
            libhogweed.hogweed[f"nettle_rsa_oaep_{hashalg}_decrypt"](
                ctypes.byref(self._pub),
                ctypes.byref(self._key),
                ctypes.byref(self.random._ctx),  # noqa: SLF001
                libnettle.nettle[f"{self.random._prefix}_random"],  # noqa: SLF001
                len(label),
                label,
                ctypes.byref(datalen),
                data,
                msg,
            )
            != 1
        ):
            raise RSAError("Failed to decrypt data")
        return bytes(data)[: datalen.value]

    def oaep_sha256_decrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Decrypt a cipher text message using RSA with the OAEP padding scheme."""
        return self._oaep_decrypt("sha256", msg, label)

    def oaep_sha384_decrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Decrypt a cipher text message using RSA with the OAEP padding scheme."""
        return self._oaep_decrypt("sha384", msg, label)

    def oaep_sha512_decrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Decrypt a cipher text message using RSA with the OAEP padding scheme."""
        return self._oaep_decrypt("sha512", msg, label)

    def oaep_sha256_encrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Encrypt a clear text message using RSA with the OAEP padding scheme."""
        return self.public_key._oaep_encrypt("sha256", msg, label)  # noqa: SLF001

    def oaep_sha384_encrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Encrypt a clear text message using RSA with the OAEP padding scheme."""
        return self.public_key._oaep_encrypt("sha384", msg, label)  # noqa: SLF001

    def oaep_sha512_encrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Encrypt a clear text message using RSA with the OAEP padding scheme."""
        return self.public_key._oaep_encrypt("sha512", msg, label)  # noqa: SLF001

    def genkey(self, n_size: int, e_size: int) -> None:
        """Generate a new RSA keypair."""
        if (
            libhogweed.hogweed.nettle_rsa_generate_keypair(
                ctypes.byref(self._pub),
                ctypes.byref(self._key),
                ctypes.byref(self.random._ctx),  # noqa: SLF001
                libnettle.nettle[f"{self.random._prefix}_random"],  # noqa: SLF001
                None,
                None,
                n_size,
                e_size,
            )
            == 0
        ):
            raise RSAError

    def sign(self, hsh: SHA1 | SHA256 | SHA512) -> bytes:
        """Sign hash."""
        signature = _MPZ_T()
        libgmp.gmp["__gmpz_init"](ctypes.byref(signature))
        hname = hsh.__class__.__name__.lower()
        libhogweed.hogweed[f"nettle_rsa_{hname}_sign"](
            ctypes.byref(self._key),
            ctypes.byref(hsh._ctx),  # noqa: SLF001
            ctypes.byref(signature),
        )
        data = ctypes.create_string_buffer(256)
        count = ctypes.c_size_t()
        libgmp.gmp["__gmpz_export"](data, ctypes.byref(count), 1, 1, 0, 0, signature)
        libgmp.gmp["__gmpz_clear"](ctypes.byref(signature))
        return bytes(data)[: count.value]

    def verify(self, signature: bytes, hsh: SHA1 | SHA256 | SHA512) -> bool:
        """Verify signature."""
        return self.public_key.verify(signature, hsh)

    def to_der(self) -> bytes:
        """Serialize key (keypair) to PKCS#1 RSAPrivateKey."""
        return RSAPrivateKey(
            Integer(0),
            Integer(_mpz_to_int(self._pub.n)),
            Integer(_mpz_to_int(self._pub.e)),
            Integer(_mpz_to_int(self._key.d)),
            Integer(_mpz_to_int(self._key.p)),
            Integer(_mpz_to_int(self._key.q)),
            Integer(_mpz_to_int(self._key.a)),
            Integer(_mpz_to_int(self._key.b)),
            Integer(_mpz_to_int(self._key.c)),
        ).to_der()

    def to_pkcs8_key(self) -> bytes:
        """Encapsulate key in PKCS #8 structure."""
        return PrivateKeyInfo(
            Integer(0),
            AlgorithmIdentifier(OID(RSAENCRYPTION), Null()),
            OctetString(self.to_der()),
        ).to_der()

    def from_pkcs1(self, data: bytes) -> None:
        """Deserialize PKCS #8 DER."""
        privkey = RSAPrivateKey.from_der(data)
        if int(privkey.version) != 0:
            raise RSAError(f"Unknown RSAPrivateKey version: {int(privkey.version) + 1}")
        self.from_params(
            n=privkey.modulus.data,
            e=privkey.public_exponent.data,
            d=privkey.private_exponent.data,
            p=privkey.prime1.data,
            q=privkey.prime2.data,
            a=privkey.exponent1.data,
            b=privkey.exponent2.data,
            c=privkey.coefficient.data,
        )

    def from_pkcs8(self, data: bytes) -> None:
        """Deserialize PKCS #8 DER."""
        pki = PrivateKeyInfo.from_der(data)
        if int(pki.version) != 0:
            raise RSAError(f"Unknown RSAPrivateKey version: {int(pki.version) + 1}")
        if str(pki.private_key_algorithm.algorithm) != RSAENCRYPTION:
            raise NotImplementedError(
                f"algorithm {pki.private_key_algorithm.algorithm} not implemented"
            )
        self.from_pkcs1(bytes(pki.private_key))

    def read_key(self, filename: str) -> None:
        """Read key from filename, DER or PEM."""
        with pathlib.Path(filename).open("rb") as f:
            pem = bytes(f.read(1))[0] != 0x30

        if pem:
            with pathlib.Path(filename).open(encoding="ascii") as f:
                data = f.read()
                m = re.search(
                    r"^-----BEGIN ([^-]+)-----$"
                    "^([^-]+)$"
                    "^-----END[^-]+-----$",
                    data,
                    re.MULTILINE,
                )
                if m:
                    keytype = m.group(1)
                    b64 = m.group(2)
                    if keytype == "RSA PRIVATE KEY":
                        self.from_pkcs1(base64.b64decode(b64))
                    elif keytype == "PRIVATE KEY":
                        self.from_pkcs8(base64.b64decode(b64))
                    else:
                        raise NotImplementedError
        else:
            with pathlib.Path(filename).open("rb") as f:
                data = f.read()
                try:
                    self.from_pkcs1(data)
                except ASN1Error:
                    self.from_pkcs8(data)

    def write_key(self, filename: str) -> None:
        """Write key to filename."""
        with pathlib.Path(filename).open("wb") as f:
            f.write(self.to_pkcs8_key())


class RSAPubKey:
    """A RSA Public Key."""

    random: Random
    _pub: _RSAPublicKey

    @property
    def size(self) -> int:
        """Get key size."""
        return self._pub.size

    def __init__(self, random: Random | None = None) -> None:
        self.random = random or Yarrow256()
        self._pub = _RSAPublicKey()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RSAPubKey):
            return False
        return all(
            [
                libgmp.gmp["__gmpz_cmp"](
                    ctypes.byref(self._pub.n), ctypes.byref(other._pub.n)
                )
                == 0,
                libgmp.gmp["__gmpz_cmp"](
                    ctypes.byref(self._pub.e), ctypes.byref(other._pub.e)
                )
                == 0,
            ]
        )

    def __hash__(self) -> int:
        return hash(self._pub)

    def encrypt(self, msg: bytes) -> bytes:
        """Encrypt data."""
        ciphertext = _MPZ_T()
        libgmp.gmp["__gmpz_init"](ctypes.byref(ciphertext))
        if (
            libhogweed.hogweed.nettle_rsa_encrypt(
                ctypes.byref(self._pub),
                ctypes.byref(self.random._ctx),  # noqa: SLF001
                libnettle.nettle[f"{self.random._prefix}_random"],  # noqa: SLF001
                len(msg),
                msg,
                ciphertext,
            )
            != 1
        ):
            raise RSAError
        datalen = libgmp.gmp["__gmpz_sizeinbase"](ctypes.byref(ciphertext), 256)
        data = (ctypes.c_byte * datalen)()
        count = ctypes.c_size_t()
        libgmp.gmp["__gmpz_export"](data, ctypes.byref(count), 1, 1, 0, 0, ciphertext)
        libgmp.gmp["__gmpz_clear"](ctypes.byref(ciphertext))
        return bytes(data)[: count.value]

    def verify(self, signature: bytes, hsh: SHA1 | SHA256 | SHA512) -> bool:
        """Verify signature."""
        sign = _MPZ_T()
        libgmp.gmp["__gmpz_init"](ctypes.byref(sign))
        libgmp.gmp["__gmpz_import"](
            ctypes.byref(sign), len(signature), 1, 1, 0, 0, signature
        )
        hname = hsh.__class__.__name__.lower()
        res = libhogweed.hogweed[f"nettle_rsa_{hname}_verify"](
            ctypes.byref(self._pub),
            ctypes.byref(hsh._ctx),  # noqa: SLF001
            ctypes.byref(sign),
        )
        libgmp.gmp["__gmpz_clear"](ctypes.byref(sign))
        return bool(res)

    def from_params(
        self,
        n: bytes,
        e: bytes,
    ) -> None:
        """Initialize keypair from params."""
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._pub.n), len(n), 1, 1, 0, 0, n)
        libgmp.gmp["__gmpz_import"](ctypes.byref(self._pub.e), len(e), 1, 1, 0, 0, e)
        if (
            libhogweed.hogweed.nettle_rsa_public_key_prepare(ctypes.byref(self._pub))
            != 1
        ):
            raise RSAError

    def to_der(self) -> bytes:
        """Serialize key to PKCS#1 RSAPublicKey."""
        return RSAPublicKey(
            Integer(_mpz_to_int(self._pub.n)),
            Integer(_mpz_to_int(self._pub.e)),
        ).to_der()

    def to_pkcs8_key(self) -> bytes:
        """Serialize key to pkcs8 DER."""
        return SubjectPublicKeyInfo(
            AlgorithmIdentifier(OID(RSAENCRYPTION), Null()),
            BitString(self.to_der()),
        ).to_der()

    def from_pkcs1(self, data: bytes) -> None:
        """Deserialize pkcs1 DER."""
        pubkey = RSAPublicKey.from_der(data)
        n = int(pubkey.modulus)
        e = int(pubkey.public_exponent)
        self.from_params(
            n=n.to_bytes(n.bit_length() // 8 + 1), e=e.to_bytes(e.bit_length() // 8 + 1)
        )

    def from_pkcs8(self, data: bytes) -> None:
        """Deserialize pkcs8 DER."""
        spki = SubjectPublicKeyInfo.from_der(data)
        if str(spki.algorithm.algorithm) != RSAENCRYPTION:
            raise ParseError("Not pkcs#8 key")
        self.from_pkcs1(bytes(spki.subject_public_key))

    def from_cert(self, data: bytes) -> None:
        """Deserialize certificate."""
        cert = Certificate.from_der(data)
        self.from_pkcs8(cert.tbs_certificate.subject_public_key_info.to_der())

    def read_key(self, filename: str) -> None:
        """Read key from PEM or DER file."""
        path = pathlib.Path(filename)
        with path.open("rb") as f:
            pem = bytes(f.read(1))[0] != 0x30

        if pem:
            with path.open("r", encoding="ascii") as f:
                data = f.read()
                m = re.search(
                    r"^-----BEGIN ([^-]+)-----$"
                    "([^-]+)"
                    "^-----END[^-]+-----$",
                    data,
                    re.MULTILINE,
                )
                if m:
                    keytype = m.group(1)
                    b64 = m.group(2)
                    if keytype == "RSA PUBLIC KEY":
                        self.from_pkcs1(base64.b64decode(b64))
                    elif keytype == "PUBLIC KEY":
                        self.from_pkcs8(base64.b64decode(b64))
                    elif keytype == "CERTIFICATE":
                        self.from_cert(base64.b64decode(b64))
                    else:
                        raise NotImplementedError
        else:
            with path.open("rb") as f:
                data = f.read()
                try:
                    self.from_pkcs1(data)
                except ASN1Error:
                    self.from_pkcs8(data)

    def write_key(self, filename: str) -> None:
        """Write key to filename."""
        with pathlib.Path(filename).open("wb") as f:
            f.write(self.to_pkcs8_key())

    def _oaep_encrypt(self, hashalg: str, msg: bytes, label: bytes) -> bytes:
        datalen = ctypes.c_size_t(self.size)
        data = ctypes.create_string_buffer(datalen.value)
        if (
            libhogweed.hogweed[f"nettle_rsa_oaep_{hashalg}_encrypt"](
                ctypes.byref(self._pub),
                ctypes.byref(self.random._ctx),  # noqa: SLF001
                libnettle.nettle[f"{self.random._prefix}_random"],  # noqa: SLF001
                len(label),
                label,
                len(msg),
                msg,
                data,
            )
            != 1
        ):
            raise RSAError("Failed to encrypt data")
        return bytes(data)

    def oaep_sha256_encrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Encrypt a clear text message using RSA with the OAEP padding scheme."""
        return self._oaep_encrypt("sha256", msg, label)

    def oaep_sha384_encrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Encrypt a clear text message using RSA with the OAEP padding scheme."""
        return self._oaep_encrypt("sha384", msg, label)

    def oaep_sha512_encrypt(self, msg: bytes, label: bytes = b"") -> bytes:
        """Encrypt a clear text message using RSA with the OAEP padding scheme."""
        return self._oaep_encrypt("sha512", msg, label)


class SLH_DSAKeyPair(KeyPair):  # noqa: N801
    """Stateless hash-based digital signature algorithm. Base class for Key Pair."""

    public_key: SLH_DSAPubKey
    key_size: int = 32
    signature_size: int
    _key: ctypes.Array[ctypes.c_char]
    _pub: ctypes.Array[ctypes.c_char]
    _prefix: str
    _pubkey_cls: type[SLH_DSAPubKey]

    def __init__(self, random: Random) -> None:
        self.random = random or Yarrow256()

    def genkey(self) -> None:
        """Generate a key pair."""
        self._key = ctypes.create_string_buffer(self.key_size)
        self._pub = ctypes.create_string_buffer(self.key_size)
        libnettle.nettle[f"{self._prefix}_generate_keypair"](
            ctypes.byref(self._pub),
            ctypes.byref(self._key),
            ctypes.byref(self.random._ctx),  # noqa: SLF001
            libnettle.nettle[f"{self.random._prefix}_random"],  # noqa: SLF001
        )
        self.public_key = self._pubkey_cls(self.random)
        self.public_key._pub = self._pub  # noqa: SLF001

    def from_param(self, key: bytes, pub: bytes) -> None:
        """Make key pair from parameters."""
        if len(key) != self.key_size or len(pub) != self.key_size:
            raise KeyLenError
        self._key = ctypes.create_string_buffer(key, size=self.key_size)
        self._pub = ctypes.create_string_buffer(pub, size=self.key_size)
        self.public_key = self._pubkey_cls(self.random)
        self.public_key._pub = self._pub  # noqa: SLF001

    def sign(self, msg: bytes) -> bytes:
        """Sign msg."""

        signature = ctypes.create_string_buffer(self.signature_size)
        libnettle.nettle[f"{self._prefix}_sign"].argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        libnettle.nettle[f"{self._prefix}_sign"](
            self._pub,
            self._key,
            len(msg),
            msg,
            signature,
        )
        return bytes(signature)

    def verify(self, msg: bytes, signature: bytes) -> bool:
        """Verify signature."""
        return self.public_key.verify(msg, signature)


class SLH_DSAPubKey(PublicKey):  # noqa: N801
    """Stateless hash-based digital signature algorithm. Base class for Public Key."""

    key_size: int = 32
    signature_size: int
    _pub: ctypes.Array[ctypes.c_char]
    _prefix: str

    def __init__(self, random: Random) -> None:
        self.random = random or Yarrow256()

    def verify(self, msg: bytes, signature: bytes) -> bool:
        """Verify signature."""
        sig = ctypes.create_string_buffer(signature)
        return (
            libnettle.nettle[f"{self._prefix}_verify"](
                ctypes.byref(self._pub),
                len(msg),
                msg,
                ctypes.byref(sig),
            )
            == 1
        )


class SLH_DSA_SHAKE_128SPubKey(SLH_DSAPubKey):  # noqa: N801
    """Stateless hash-based digital signature Public Key. SHAKE256 based and small."""

    signature_size = 7856
    _prefix = "nettle_slh_dsa_shake_128s"


class SLH_DSA_SHAKE_128SKeyPair(SLH_DSAKeyPair):  # noqa: N801
    """Stateless hash-based digital signature Key Pair. SHAKE256 based and small."""

    signature_size = 7856
    _prefix = "nettle_slh_dsa_shake_128s"
    _pubkey_cls = SLH_DSA_SHAKE_128SPubKey


class SLH_DSA_SHAKE_128FPubKey(SLH_DSAPubKey):  # noqa: N801
    """Stateless hash-based digital signature Public Key. SHAKE256 based and small."""

    signature_size = 17088
    _prefix = "nettle_slh_dsa_shake_128f"


class SLH_DSA_SHAKE_128FKeyPair(SLH_DSAKeyPair):  # noqa: N801
    """Stateless hash-based digital signature algorithm. SHAKE256 based and fast."""

    signature_size = 17088
    _prefix = "nettle_slh_dsa_shake_128f"
    _pubkey_cls = SLH_DSA_SHAKE_128FPubKey


class SLH_DSA_SHA2_128SPubKey(SLH_DSAPubKey):  # noqa: N801
    """Stateless hash-based digital signature Public Key. SHAKE256 based and small."""

    signature_size = 7856
    _prefix = "nettle_slh_dsa_sha2_128s"


class SLH_DSA_SHA2_128SKeyPair(SLH_DSAKeyPair):  # noqa: N801
    """Stateless hash-based digital signature algorithm. SHA256 based and small."""

    signature_size = 7856
    _prefix = "nettle_slh_dsa_sha2_128s"
    _pubkey_cls = SLH_DSA_SHA2_128SPubKey


class SLH_DSA_SHA2_128FPubKey(SLH_DSAPubKey):  # noqa: N801
    """Stateless hash-based digital signature algorithm. SHA256 based and small."""

    signature_size = 17088
    _prefix = "nettle_slh_dsa_sha2_128f"


class SLH_DSA_SHA2_128FKeyPair(SLH_DSAKeyPair):  # noqa: N801
    """Stateless hash-based digital signature algorithm. SHA256 based and fast."""

    signature_size = 17088
    _prefix = "nettle_slh_dsa_sha2_128f"
    _pubkey_cls = SLH_DSA_SHA2_128FPubKey
