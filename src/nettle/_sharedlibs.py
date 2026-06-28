import os
import pathlib


def find_libs(glob: str) -> set[str]:
    libs = set()

    searchdirs = [
        "/opt/homebrew/lib",
        "/opt/local/lib",
        "/opt/local/lib64",
        "/usr/lib",
        "/usr/lib/x86_64-linux-gnu/",
        "/usr/lib64",
        "/usr/local/lib",
        "/usr/local/lib64",
    ]

    if "LD_LIBRARY_PATH" in os.environ:
        searchdirs.extend(os.environ["LD_LIBRARY_PATH"].split(":"))

    for instdir in searchdirs:
        libdir = pathlib.Path(instdir)
        libs.update({lib.resolve() for lib in libdir.glob(glob)})
    return libs
