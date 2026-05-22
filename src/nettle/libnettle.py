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
import pathlib
import sys


class LibnettleError(Exception):
    """Failed to load libnettle."""


class Libnettle:
    """A class keeping a reference to the dynamically loaded nettle lib."""

    nettle: ctypes.CDLL
    major: int
    minor: int
    verbose: bool = False

    def __init__(self) -> None:
        glob = "libnettle*.dylib" if sys.platform == "darwin" else "libnettle.so*"
        libs = set()

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
        versions = []
        for dld in libs:
            with contextlib.suppress(OSError):
                nettle = ctypes.cdll.LoadLibrary(dld)
                major = nettle.nettle_version_major()
                minor = nettle.nettle_version_minor()
                versions.append((major, minor, nettle))
        if len(versions) == 0:
            raise LibnettleError
        versions.sort()
        self.major, self.minor, self.nettle = versions[-1]
        if self.verbose:
            print(f"nettle {self.major}.{self.minor} loaded")  # noqa: T201


libnettle = Libnettle()
