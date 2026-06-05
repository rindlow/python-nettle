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

"""Interface to the hogweed C library."""

import ctypes
import pathlib
import sys


class LibhogweedError(Exception):
    """Failed to load libnettle."""


class Libhogweed:
    """A class keeping a reference to the dynamically loaded nettle lib."""

    hogweed: ctypes.CDLL
    verbose: bool = True

    def __init__(self) -> None:
        glob = "libhogweed*.dylib" if sys.platform == "darwin" else "libhogweed.so*"
        libs: set[pathlib.Path] = set()

        for instdir in [
            "/usr/lib",
            "/usr/lib64",
            "/usr/local/lib",
            "/usr/local/lib64",
            "/opt/local/lib",
            "/opt/local/lib64",
            "/opt/homebrew/lib",
        ]:
            libdir = pathlib.Path(instdir)
            libs.update({lib.resolve() for lib in libdir.glob(glob)})
        if len(libs) == 0:
            raise LibhogweedError
        dld = sorted(libs)[-1]
        self.hogweed = ctypes.cdll.LoadLibrary(str(dld))
        if self.verbose:
            print(f"hogweed ({dld}) loaded")  # noqa: T201


libhogweed = Libhogweed()
