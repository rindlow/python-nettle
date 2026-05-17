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
