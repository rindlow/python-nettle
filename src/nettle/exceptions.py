#
# exception.py
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

"""Nettle exceptions."""


class AuthenticationError(Exception):
    """Wrapped key is not authenticated.."""


class DataLenError(Exception):
    """Data length not multiple of block size."""


class KeyLenError(Exception):
    """Key not of expected length."""


class NotInitializedError(Exception):
    """Cipher not initialized."""


class RSAError(Exception):
    """Error in RSA."""


class ShortSeedError(Exception):
    """Seed is not of the required size."""
