"""Test utilities."""


def sdata(string: str) -> bytes:
    return string.encode("ascii")


def shex(hexstring: str) -> bytes:
    return bytes.fromhex(hexstring)
