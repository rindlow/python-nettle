"""Test utilities."""

import pathlib


def sdata(string: str) -> bytes:
    return string.encode("ascii")


def shex(hexstring: str) -> bytes:
    return bytes.fromhex(hexstring)


def read_hex_file(filename: str) -> bytes:
    path = pathlib.Path(__file__).with_name(filename)
    with path.open("r", encoding="ascii") as f:
        return bytes.fromhex(f.read())
