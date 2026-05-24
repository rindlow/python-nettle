#
# randomness.py
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

"""Nettle randomness functions."""

import ctypes
import random

from .aead import _NettleBlock16
from .ciphers import AES256, _AES256ctx
from .exceptions import ShortSeedError
from .hashes import _SHA256Ctx
from .libnettle import libnettle


class _RandomCtx(ctypes.Structure):
    """Base class for random contexts."""


class Random:
    """Base class for random functions."""

    _ctx: _RandomCtx
    _ctxclass: type[_RandomCtx]
    _prefix: str
    _seed_size: int

    def __init__(self, seed: bytes | None = None) -> None:
        self._ctx = self._ctxclass()

        if seed is None:
            # No seed is given, seed with system random
            seed = random.randbytes(self._seed_size)  # noqa: S311
        if len(seed) < self._seed_size:
            raise ShortSeedError
        self._initialize(seed)

    def _initialize(self, seed: bytes) -> None:
        pass

    def random(self, length: int) -> bytes:
        """Generate length bytes of randomness."""
        data = (ctypes.c_uint8 * length)()
        libnettle.nettle[f"{self._prefix}_random"](
            ctypes.byref(self._ctx), length, data
        )
        return bytes(data)


class _Yarrow256Ctx(_RandomCtx):
    _fields_ = [
        ("pools", _SHA256Ctx * 2),
        ("seeded", ctypes.c_int),
        ("key", _AES256ctx),
        ("counter", ctypes.c_uint8 * AES256.block_size),
        ("nsources", ctypes.c_uint),
        ("sources", ctypes.c_void_p),
    ]


class Yarrow256(Random):
    """Yarrow is a family of pseudo-randomness generators."""

    _prefix = "nettle_yarrow256"
    _ctxclass = _Yarrow256Ctx
    _seed_size = 2 * AES256.block_size

    def _initialize(self, seed: bytes) -> None:
        libnettle.nettle.nettle_yarrow256_init(ctypes.byref(self._ctx), 0, None)
        libnettle.nettle.nettle_yarrow256_seed(ctypes.byref(self._ctx), len(seed), seed)


class _DRBG_CTR_AES256Ctx(_RandomCtx):  # noqa: N801
    _fields_ = [
        ("key", _AES256ctx),
        ("V", _NettleBlock16),
    ]


class DRBG_CTR_AES256(Random):  # noqa: N801
    """The Deterministic Random Bit Generator (DRBG)."""

    _prefix = "nettle_drbg_ctr_aes256"
    _ctxclass = _DRBG_CTR_AES256Ctx
    _seed_size = AES256.block_size + AES256.key_size

    def _initialize(self, seed: bytes) -> None:
        libnettle.nettle.nettle_drbg_ctr_aes256_init(ctypes.byref(self._ctx), seed)
