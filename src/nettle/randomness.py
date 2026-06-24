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

from .ciphers import AES256
from .exceptions import ShortSeedError
from .libnettle import libnettle


class Random:
    """Base class for random functions."""

    _ctx: ctypes.Array[ctypes.c_char]
    _ctx_size: int
    _prefix: str
    _seed_size: int

    def __init__(self, seed: bytes | None = None) -> None:
        self._ctx = ctypes.create_string_buffer(self._ctx_size)

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
        data = ctypes.create_string_buffer(length)
        libnettle.nettle[f"{self._prefix}_random"](
            ctypes.byref(self._ctx), length, data
        )
        return bytes(data)


class Yarrow256(Random):
    """Yarrow is a family of pseudo-randomness generators."""

    _prefix = "nettle_yarrow256"
    _ctx_size = 512
    _seed_size = 2 * AES256.block_size

    def _initialize(self, seed: bytes) -> None:
        libnettle.nettle.nettle_yarrow256_init(ctypes.byref(self._ctx), 0, None)
        libnettle.nettle.nettle_yarrow256_seed(ctypes.byref(self._ctx), len(seed), seed)


class DRBG_CTR_AES256(Random):  # noqa: N801
    """The Deterministic Random Bit Generator (DRBG)."""

    _prefix = "nettle_drbg_ctr_aes256"
    _ctx_size = 256
    _seed_size = AES256.block_size + AES256.key_size

    def _initialize(self, seed: bytes) -> None:
        if libnettle.major < 3 or (libnettle.major == 3 and libnettle.minor < 10):
            raise NotImplementedError("DRBG first appeared in nettle 3.10")
        libnettle.nettle.nettle_drbg_ctr_aes256_init(ctypes.byref(self._ctx), seed)
