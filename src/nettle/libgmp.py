#
# libnettle.py
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

"""Interface to the nettle C library."""

import contextlib
import ctypes
import sys

from ._sharedlibs import find_libs


class LibgmpError(Exception):
    """Failed to load libnettle."""


class Libgmp:
    """A class keeping a reference to the dynamically loaded nettle lib."""

    gmp: ctypes.CDLL
    version: str
    verbose: bool = True

    def __init__(self) -> None:
        versions = []
        glob = "libgmp*.dylib" if sys.platform == "darwin" else "libgmp.so*"
        for dld in find_libs(glob):
            with contextlib.suppress(OSError):
                gmp = ctypes.cdll.LoadLibrary(dld)
                version = ctypes.c_char_p.in_dll(gmp, "__gmp_version").value
                if version is not None:
                    versions.append((version.decode(), dld))
        if len(versions) == 0:
            raise LibgmpError
        versions.sort()
        self.version, dld = versions[-1]
        self.gmp = ctypes.cdll.LoadLibrary(dld)
        if self.verbose:
            print(f"gmp {self.version} loaded")  # noqa: T201


libgmp = Libgmp()
