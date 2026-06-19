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
from abc import abstractmethod
from dataclasses import dataclass
from typing import Self

from nettle.asn1 import (
    OID,
    ASN1Error,
    BitString,
    Integer,
    OctetString,
)
from nettle.asn1types import (
    AlgorithmIdentifier,
    Certificate,
    PrivateKeyInfo,
    SubjectPublicKeyInfo,
)
from nettle.exceptions import KeyLenError, ParseError
from nettle.libnettle import libnettle
from nettle.randomness import Random, Yarrow256

__all__ = [
    "KeyPair",
    "PubKey",
    "SLHDSAKeyPair",
    "SLHDSAPubKey",
]


@dataclass
class PKParam:
    signature_size: int
    oid: str
    pkcs1tag: str = ""


SLH_OID = {
    "2.16.840.1.101.3.4.3.20": "slh_dsa_shake_128s",
    "2.16.840.1.101.3.4.3.21": "slh_dsa_shake_128f",
    "2.16.840.1.101.3.4.3.26": "slh_dsa_sha2_128s",
    "2.16.840.1.101.3.4.3.27": "slh_dsa_sha2_128f",
}
SLH_PARAM = {
    "slh_dsa_shake_128s": PKParam(signature_size=7856, oid="2.16.840.1.101.3.4.3.20"),
    "slh_dsa_shake_128f": PKParam(signature_size=17088, oid="2.16.840.1.101.3.4.3.21"),
    "slh_dsa_sha2_128s": PKParam(signature_size=7856, oid="2.16.840.1.101.3.4.3.26"),
    "slh_dsa_sha2_128f": PKParam(signature_size=17088, oid="2.16.840.1.101.3.4.3.27"),
}


def _pem(data: bytes, tag: str) -> str:
    linelen = 64
    s = [f"-----BEGIN {tag}-----"]
    b = base64.b64encode(data).decode()
    s.extend(b[i : i + linelen] for i in range(0, len(b), linelen))
    s.append(f"-----END {tag}-----\n")
    return "\n".join(s)


class PubKey:
    """Base class for Public Keys."""

    _alg: str
    _oids: dict[str, str]
    _params: dict[str, PKParam]

    def write_key_as_pem(self, filename: str) -> None:
        """Write key to filename in PEM format."""
        pathlib.Path(filename).write_text(_pem(self.to_pkcs8(), "PUBLIC KEY"))

    def write_key(self, filename: str) -> None:
        """Write key to filename."""
        pathlib.Path(filename).write_bytes(self.to_pkcs8())

    @abstractmethod
    def to_pkcs8(self) -> bytes:
        """Serialize self to PKCS#8."""

    @classmethod
    def from_file(cls, filename: str, random: Random | None = None) -> Self:
        """Read key from PEM or DER file."""
        path = pathlib.Path(filename)
        with path.open("rb") as f:
            pem = bytes(f.read(1))[0] != 0x30

        if pem:
            data = path.read_text(encoding="ascii")
            m = re.search(
                r"-----BEGIN ([^-]+)-----\s+^([^-]+)\s+-----END[^-]+-----",
                data,
                re.MULTILINE,
            )
            if m:
                keytype = m.group(1)
                b64 = m.group(2)
                if hasattr(cls, "_alg") and keytype == cls._params[cls._alg].pkcs1tag:
                    return cls._from_public_key_bit_string(
                        base64.b64decode(b64), cls._alg, random
                    )
                if keytype == "PUBLIC KEY":
                    return cls.from_pkcs8(base64.b64decode(b64), random)
                if keytype == "CERTIFICATE":
                    return cls.from_cert(base64.b64decode(b64), random)
                raise NotImplementedError
            raise ParseError("Failed to parse PEM file")

        data = path.read_bytes()
        if hasattr(cls, "_alg"):
            try:
                return cls._from_public_key_bit_string(data, cls._alg, random)
            except ASN1Error:
                pass
        return cls.from_pkcs8(data, random)

    @classmethod
    def from_cert(cls, data: bytes, random: Random | None = None) -> Self:
        """Deserialize certificate."""
        cert = Certificate.from_der(data)
        return cls._from_subject_public_key_info(
            cert.tbs_certificate.subject_public_key_info, random
        )

    @classmethod
    def from_pkcs8(cls, data: bytes, random: Random | None = None) -> Self:
        """Deserialize PKCS#8."""
        return cls._from_subject_public_key_info(
            SubjectPublicKeyInfo.from_der(data), random
        )

    @classmethod
    def _from_subject_public_key_info(
        cls, spki: SubjectPublicKeyInfo, random: Random | None = None
    ) -> Self:
        algid = str(spki.algorithm.algorithm)
        if algid not in cls._oids:
            raise NotImplementedError(f"Algorithm '{algid}' not implemented")
        return cls._from_public_key_bit_string(
            bytes(spki.subject_public_key), cls._oids[algid], random
        )

    @classmethod
    @abstractmethod
    def _from_public_key_bit_string(
        cls, data: bytes, alg: str, random: Random | None
    ) -> Self: ...


class KeyPair:
    """Base class for Key Pairs."""

    public_key: PubKey
    random: Random
    _alg: str
    _oids: dict[str, str]
    _params: dict[str, PKParam]

    @abstractmethod
    def to_pkcs8(self) -> bytes:
        """Serialize self to PKCS#8."""

    def write_key_as_pem(self, filename: str) -> None:
        """Write key to filename in PEM format."""
        pathlib.Path(filename).write_text(_pem(self.to_pkcs8(), "PRIVATE KEY"))

    def write_key(self, filename: str) -> None:
        """Write key to filename."""
        pathlib.Path(filename).write_bytes(self.to_pkcs8())

    @classmethod
    def from_file(cls, filename: str, random: Random | None = None) -> Self:
        """Read key from filename, DER or PEM."""
        with pathlib.Path(filename).open("rb") as f:
            pem = bytes(f.read(1))[0] != 0x30

        if pem:
            with pathlib.Path(filename).open(encoding="ascii") as f:
                data = f.read()
                m = re.search(
                    r"-----BEGIN ([^-]+)-----\s+^([^-]+)\s+-----END[^-]+-----",
                    data,
                    re.MULTILINE,
                )
                if m:
                    keytype = m.group(1)
                    b64 = m.group(2)
                    if (
                        hasattr(cls, "_alg")
                        and keytype == cls._params[cls._alg].pkcs1tag
                    ):
                        return cls._from_private_key_octet_string(
                            base64.b64decode(b64), cls._alg, random
                        )
                    if keytype == "PRIVATE KEY":
                        return cls.from_pkcs8(base64.b64decode(b64), random)
                    raise NotImplementedError
                raise ParseError("Failed to parse PEM file")
        else:
            with pathlib.Path(filename).open("rb") as f:
                data = f.read()
                if hasattr(cls, "_alg"):
                    try:
                        return cls._from_private_key_octet_string(
                            data, cls._alg, random
                        )
                    except ASN1Error:
                        pass
                return cls.from_pkcs8(data, random)

    @classmethod
    def _from_private_key_info(
        cls, pki: PrivateKeyInfo, random: Random | None = None
    ) -> Self:
        if int(pki.version) != 0:
            raise ParseError(f"Unknown PrivateKeyInfo version: {int(pki.version) + 1}")
        algid = str(pki.private_key_algorithm.algorithm)
        if algid not in cls._oids:
            raise NotImplementedError(f"Algorithm '{algid}' not implemented")
        return cls._from_private_key_octet_string(
            bytes(pki.private_key), cls._oids[algid], random
        )

    @classmethod
    @abstractmethod
    def from_pkcs8(cls, data: bytes, random: Random | None = None) -> Self:
        """Deserialize PKCS #8 DER."""

    @classmethod
    @abstractmethod
    def _from_private_key_octet_string(
        cls,
        data: bytes,
        alg: str,
        random: Random | None = None,
    ) -> Self: ...


######################################################################
# SLH-DSA


class SLHDSAKeyPair(KeyPair):
    """Stateless hash-based digital signature algorithm. Base class for Key Pair."""

    public_key: SLHDSAPubKey
    key_size: int = 32
    signature_size: int
    random: Random
    _key: ctypes.Array[ctypes.c_char]
    _pub: ctypes.Array[ctypes.c_char]
    _prefix: str
    _oids = SLH_OID
    _params = SLH_PARAM

    def __init__(self, alg: str, random: Random | None = None) -> None:
        """Generate a key pair."""
        if libnettle.major < 4:
            raise NotImplementedError("SLH-DSA first appeared in nettle 4.0")
        if alg not in SLH_PARAM:
            raise NotImplementedError(f"SLH-DSA '{alg}' not implemented")

        self.signature_size = SLH_PARAM[alg].signature_size
        self.random = random or Yarrow256()
        self._key = ctypes.create_string_buffer(self.key_size)
        self._pub = ctypes.create_string_buffer(self.key_size)
        self._alg = alg
        self._prefix = f"nettle_{alg}"
        libnettle.nettle[f"{self._prefix}_generate_keypair"](
            ctypes.byref(self._pub),
            ctypes.byref(self._key),
            ctypes.byref(self.random._ctx),  # noqa: SLF001
            libnettle.nettle[f"{self.random._prefix}_random"],  # noqa: SLF001
        )
        self.public_key = SLHDSAPubKey()
        self.public_key.signature_size = self.signature_size
        self.public_key._pub = self._pub  # noqa: SLF001
        self.public_key._prefix = self._prefix  # noqa: SLF001
        self.public_key._alg = self._alg  # noqa: SLF001

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

    def to_pkcs8(self) -> bytes:
        """Encapsulate key in PKCS #8 structure."""
        return PrivateKeyInfo(
            Integer(0),
            AlgorithmIdentifier.without_params(OID(self._params[self._alg].oid)),
            OctetString(bytes(self)),
        ).to_der()

    def __bytes__(self) -> bytes:
        return bytes(self._key) + bytes(self._pub)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SLHDSAKeyPair):
            return False
        return bytes(self) == bytes(other)

    def __hash__(self) -> int:
        return hash(bytes(self))

    @classmethod
    def slh_dsa_shake_128s(cls, random: Random | None = None) -> Self:
        """Generate a slh_dsa_shake_128s key pair."""
        return cls("slh_dsa_shake_128s", random)

    @classmethod
    def slh_dsa_shake_128f(cls, random: Random | None = None) -> Self:
        """Generate a slh_dsa_shake_128f key pair."""
        return cls("slh_dsa_shake_128f", random)

    @classmethod
    def slh_dsa_sha2_128s(cls, random: Random | None = None) -> Self:
        """Generate a slh_dsa_shake_128s key pair."""
        return cls("slh_dsa_sha2_128s", random)

    @classmethod
    def slh_dsa_sha2_128f(cls, random: Random | None = None) -> Self:
        """Generate a slh_dsa_shake_128s key pair."""
        return cls("slh_dsa_sha2_128f", random)

    @classmethod
    def from_pkcs8(cls, data: bytes, random: Random | None = None) -> Self:
        """Make key pair from pkcs8 der."""
        return cls._from_private_key_info(PrivateKeyInfo.from_der(data), random)

    @classmethod
    def from_params(
        cls, key: bytes, pub: bytes, alg: str, random: Random | None = None
    ) -> Self:
        """Make key pair from parameters."""
        if alg not in cls._params:
            raise NotImplementedError(f"SLH-DSA '{alg}' not implemented")

        keypair = cls.__new__(cls)
        if len(key) != keypair.key_size or len(pub) != keypair.key_size:
            raise KeyLenError
        keypair.signature_size = cls._params[alg].signature_size
        keypair.random = random or Yarrow256()
        keypair._prefix = f"nettle_{alg}"  # noqa: SLF001
        keypair._key = ctypes.create_string_buffer(key, size=keypair.key_size)  # noqa: SLF001
        keypair._pub = ctypes.create_string_buffer(pub, size=keypair.key_size)  # noqa: SLF001
        keypair._alg = alg  # noqa: SLF001
        keypair.public_key = SLHDSAPubKey()
        keypair.public_key._pub = keypair._pub  # noqa: SLF001
        keypair.public_key._prefix = keypair._prefix  # noqa: SLF001
        keypair.public_key._alg = alg  # noqa: SLF001
        return keypair

    @classmethod
    def _from_private_key_octet_string(
        cls, data: bytes, alg: str, random: Random | None = None
    ) -> Self:
        if len(data) != cls.key_size * 2:
            raise KeyLenError
        return cls.from_params(data[: cls.key_size], data[cls.key_size :], alg, random)


class SLHDSAPubKey(PubKey):
    """Stateless hash-based digital signature algorithm. Base class for Public Key."""

    key_size: int = 32
    signature_size: int
    _oids = SLH_OID
    _params = SLH_PARAM
    _pub: ctypes.Array[ctypes.c_char]
    _alg: str
    _prefix: str

    def __init__(self) -> None:
        if libnettle.major < 4:
            raise NotImplementedError("SLH-DSA first appeared in nettle 4.0")

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

    def to_pkcs8(self) -> bytes:
        """Serialize key to pkcs8 DER."""
        return SubjectPublicKeyInfo(
            AlgorithmIdentifier.without_params(OID(self._params[self._alg].oid)),
            BitString(bytes(self)),
        ).to_der()

    def __bytes__(self) -> bytes:
        return bytes(self._pub)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SLHDSAPubKey):
            return False
        return bytes(self) == bytes(other)

    def __hash__(self) -> int:
        return hash(bytes(self))

    @classmethod
    def _from_public_key_bit_string(
        cls, data: bytes, alg: str, random: Random | None = None
    ) -> Self:
        return cls.from_params(data, alg, random)

    @classmethod
    def from_pkcs8(cls, data: bytes, random: Random | None = None) -> Self:
        """Make key pair from pkcs8 der."""
        return cls._from_subject_public_key_info(
            SubjectPublicKeyInfo.from_der(data), random
        )

    @classmethod
    def from_params(cls, pubkey: bytes, alg: str, random: Random | None = None) -> Self:
        """Create public key from bytes."""
        if alg not in SLH_PARAM:
            raise NotImplementedError(f"SLH-DSA '{alg}' not implemented")
        pk = cls.__new__(cls)
        pk._pub = pubkey  # noqa: SLF001
        pk._alg = alg  # noqa: SLF001
        pk.signature_size = SLH_PARAM[alg].signature_size
        pk.random = random
        return pk
