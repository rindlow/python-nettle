"""
Asn.1 parser.

For a good primer on ASN.1, see Kaliski's
"A Layman's Guide to a Subset of ASN.1, BER, and DER".
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    import collections.abc


class ASN1Error(Exception):
    """Base Exception."""


class ParseError(ASN1Error):
    """Error parsing ASN1."""


class TagError(ASN1Error):
    """Object has the wrong tag."""


class OutOfBoundsError(ASN1Error):
    """Object does not have that many children."""


def encodelen(obj: collections.abc.Sized) -> bytes:
    """Encode length in 1-5 bytes."""
    length = len(obj)
    bitlen = length.bit_length()
    if bitlen < 8:
        return bytes([length])
    bytelen = bitlen // 8
    if bitlen % 8 != 0:
        bytelen += 1
    return bytes([0x80 | bytelen]) + length.to_bytes(bytelen)


class Object:
    """Hold a ASN.1 object."""

    tag_class: int
    _is_constructed: bool
    tag: int
    _datalen: int
    _headerlen: int
    _offset: int
    _header: bytes
    _data: bytes
    children: list[Object]

    def __repr__(self) -> str:
        """Return a string representation of object and it's children."""
        return self.describe()

    def describe(self, indent: int = 0) -> str:  # noqa: C901,PLR0912
        """Describe object as a string."""
        constructed: Sequence | Set | None = None
        s: str = "| " * indent
        if self.tag_class == 0:
            if self.tag == 1:
                s += repr(Boolean.from_object(self))
            elif self.tag == 2:
                s += repr(Integer.from_object(self))
            elif self.tag == 3:
                s += repr(BitString.from_object(self))
            elif self.tag == 4:
                s += repr(OctetString.from_object(self))
            elif self.tag == 5:
                s += repr(Null.from_object(self))
            elif self.tag == 6:
                s += repr(OID.from_object(self))
            elif self.tag == 16:
                s += "SEQUENCE"
                constructed = Sequence.from_object(self)
            elif self.tag == 17:
                s += "SET"
                constructed = Set.from_object(self)
            elif self.tag == 19:
                s += repr(PrintableString.from_object(self))
            elif self.tag == 23:
                s += repr(UTCTime.from_object(self))
            elif self.tag == 24:
                s += repr(GeneralizedTime.from_object(self))
        elif self.tag_class == 2:
            s += f"CONTEXT [{self.tag}]"
            constructed = Sequence.from_object(self, context=self.tag)
        else:
            s += f"<UNKNOWN {self.tag_class}:{self._is_constructed}:{self.tag}>"
        if constructed is not None:
            for item in constructed.children:
                s += "\n"
                s += item.describe(indent + 1)
        return s

    @classmethod
    def from_object(cls, obj: Object, context: int | None = None) -> Self:
        """Cast a basic object to class."""
        if context is None and (
            (hasattr(cls, "tag") and obj.tag != cls.tag)
            or (hasattr(cls, "tag_class") and obj.tag_class != cls.tag_class)
        ):
            raise TagError
        if context is not None and (obj.tag_class != 2 or obj.tag != context):
            raise TagError

        self = cls.__new__(cls)
        self.tag = obj.tag
        self.tag_class = obj.tag_class
        self._data = obj._data
        self._datalen = obj._datalen
        self._parse_data()
        return self

    @classmethod
    def from_der(cls, data: bytes) -> Self:
        """Parse a DER structure."""
        i = 0
        # Parse identifier
        b = data[i]
        tag_class = b >> 6
        is_constructed = ((b >> 5) & 1) == 1
        if (b & 0x1F) != 0x1F:
            tag = b & 0x1F
        else:
            tag = 0
            while True:
                i += 1
                b = data[i]
                tag <<= 7
                tag |= b & 0x7F
                if b & 0x80 == 0:
                    break
        if (hasattr(cls, "tag") and tag != cls.tag) or (
            hasattr(cls, "tag_class") and tag_class != cls.tag_class
        ):
            raise TagError

        # Parse length
        i += 1
        b = data[i]
        if b & 0x80 == 0:
            datalen = b
        else:
            lenlen = b & 0x7F
            if lenlen > 4:
                raise ParseError
            datalen = 0
            for _ in range(lenlen):
                i += 1
                datalen <<= 8
                datalen |= data[i]

        i += 1
        self = cls.__new__(cls)
        self._headerlen = i
        self._datalen = datalen
        self._is_constructed = is_constructed
        self._header = data[:i]
        self._data = data[i : i + datalen]
        self.tag = tag
        self.tag_class = tag_class
        self._parse_data()
        return self

    def _parse_data(self) -> None:
        pass

    def to_der(self) -> bytes:
        """Serialize self to DER format."""
        return self._header + self._data

    def is_context(self, tag: int) -> bool:
        """Return true if object is CONTEXT [tag]."""
        return self.tag_class == 2 and self.tag == tag


class Boolean(Object):
    """A BOOLEAN."""

    tag = 1
    value: bool

    def __init__(self, arg: bool) -> None:  # noqa: FBT001
        self.value = arg

    def __bool__(self) -> bool:
        return self.value

    def __repr__(self) -> str:
        return f"BOOLEAN {self.value}"

    def _parse_data(self) -> None:
        if len(self._data) < 1:
            raise ParseError
        self.value = self._data[0] != 0

    def to_der(self) -> bytes:
        """Serialize self to DER format."""
        return bytes([1, 1, 255 if self.value else 0])


class Integer(Object):
    """An INTEGER."""

    tag = 2
    value: int

    def __init__(self, arg: int) -> None:
        """Initialize an integer."""
        self.value = arg

    def __int__(self) -> int:
        return self.value

    def __bytes__(self) -> bytes:
        if hasattr(self, "_data"):
            return self._data
        blen = self.value.bit_length()
        n = blen // 8 + 1
        return self.value.to_bytes(n, signed=True)

    def __repr__(self) -> str:
        return f"INTEGER {self.value}"

    def _parse_data(self) -> None:
        if self.tag != 2:
            raise TagError
        if len(self._data) < 1:
            raise ParseError
        self.value = int.from_bytes(self._data, signed=True)

    def to_der(self) -> bytes:
        """Serialize self to DER format."""
        blen = self.value.bit_length()
        n = blen // 8 + 1
        b = self.value.to_bytes(n, signed=True)
        if n > 1 and b[0] == 0xFF and b[1] & 0x80 != 0:
            n -= 1
            b = b[1:]
        return b"\x02" + encodelen(b) + b


class BaseString(Object):
    """Base class for string objects."""

    tag = 0
    value: bytes

    def __init__(self, arg: bytes) -> None:
        """Initialize a string with a bytes value."""
        self.value = arg

    def __bytes__(self) -> bytes:
        return self.value

    def _parse_data(self) -> None:
        self.value = self._data

    def to_der(self) -> bytes:
        """Serialize self to DER format."""
        return bytes([self.tag]) + encodelen(self.value) + self.value


class BitString(BaseString):
    """A BIT STRING."""

    tag = 3
    value: bytes
    unused_bits: int

    def __init__(self, arg: bytes, unused_bits: int = 0) -> None:
        """Initialize a string with a bytes value."""
        self.value = arg
        self.unused_bits = unused_bits

    def __bytes__(self) -> bytes:
        return self.value

    def _parse_data(self) -> None:
        self.unused_bits = int(self._data[0])
        self.value = self._data[1:]

    def to_der(self) -> bytes:
        """Serialize self to DER format."""
        data = bytes([self.unused_bits]) + self.value
        return bytes([self.tag]) + encodelen(data) + data

    def __repr__(self) -> str:
        return f"BIT STRING {self.value.hex()}"


class OctetString(BaseString):
    """An OCTET STRING."""

    tag = 4

    def __repr__(self) -> str:
        return f"OCTET STRING {self.value.hex()}"


class Null(Object):
    """The NULL Object."""

    tag = 5

    def __init__(self) -> None:
        pass

    def __repr__(self) -> str:
        return "NULL"

    def _parse_data(self) -> None:
        self.value = None

    def to_der(self) -> bytes:
        """Serialize self to DER format."""
        return bytes([5, 0])


class OID(Object):
    """An OBJECT IDENTIFIER object."""

    tag = 6
    value: list[int]

    def __init__(self, arg: str) -> None:
        """Initialize a oid with a dotted string."""
        self.value = [int(x) for x in arg.split(".")]

    def __repr__(self) -> str:
        return f"OBJECT IDENTIFIER {self.value}"

    def _parse_data(self) -> None:
        oid = [self._data[0] // 40, self._data[0] % 40]
        value = 0
        for b in self._data[1:]:
            value <<= 7
            value |= b & 0x7F
            if b & 0x80 == 0:
                oid.append(value)
                value = 0
        self.value = oid

    def __str__(self) -> str:
        return ".".join(str(x) for x in self.value)

    def to_der(self) -> bytes:
        """Serialize self to DER format."""
        b = [40 * self.value[0] + self.value[1]]
        for i in self.value[2:]:
            n: list[int] = []
            value = i
            while True:
                a = value & 0x7F
                if len(n) > 0:
                    n.append(a | 0x80)
                else:
                    n.append(a)
                value >>= 7
                if value == 0:
                    break
            b.extend(reversed(n))

        return bytes([6, len(b)]) + bytes(b)


class Constructed(Object):
    """A constructed object."""

    is_constructed = True
    children: list[Object]

    def __init__(self, *children: Object) -> None:
        """Initialize a constructed object with a list of objects."""
        self.children = list(children)

    def _parse_data(self) -> None:
        self.children = []
        offset = 0
        while offset < self._datalen:
            obj = Object().from_der(self._data[offset:])
            offset += obj._headerlen + obj._datalen  # noqa: SLF001
            self.children.append(obj)
        self._assign_children()

    def _assign_children(self) -> None:
        pass

    def to_der(self) -> bytes:
        """Serialize self to DER format."""
        b = b"".join(item.to_der() for item in self.children)
        return bytes([0x20 | self.tag]) + encodelen(b) + b


class UTF8String(BaseString):
    """An UTF8String."""

    tag = 12

    def __repr__(self) -> str:
        return f"UTF8String '{self.value.decode('utf8')}'"


class Sequence(Constructed):
    """A SEQUENCE object."""

    tag = 16

    def __repr__(self) -> str:
        s = "SEQUENCE\n"
        for child in self.children:
            s += f"    {child!r}\n"
        return s


class Set(Constructed):
    """A SET object."""

    tag = 17

    def __repr__(self) -> str:
        s = "SET\n"
        for child in self.children:
            s += f"    {child!r}\n"
        return s


class PrintableString(BaseString):
    """A PrintableString."""

    tag = 19

    def __repr__(self) -> str:
        return f"PrintableString '{self.value.decode()}'"


class UTCTime(BaseString):
    """UTC Time."""

    tag = 23

    def __repr__(self) -> str:
        return f"UTCTime '{self.value}'"


class GeneralizedTime(BaseString):
    """Generalized Time."""

    tag = 24

    def __repr__(self) -> str:
        return f"GeneralizedTime '{self.value}'"


class ContextSpecific(Constructed):
    """a context specific (constructed) object."""

    def __init__(self, tag: int, obj: Object) -> None:
        """Initialize a context specific (constructed) object."""
        self.tag = 0x80 | tag
        self.children = [obj]

    def _parse_data(self) -> None:
        self.children = []
        offset = 0
        while offset < self._datalen:
            obj = Object().from_der(self._data[offset:])
            offset += obj._headerlen + obj._datalen  # noqa: SLF001
            self.children.append(obj)
        if len(self.children) != 1:
            raise ParseError("CONTEXT with number of children != 1")
        self._assign_children()

    def to_der(self) -> bytes:
        """Serialize self to DER format."""
        b = b"".join(item.to_der() for item in self.children)
        return bytes([0x20 | self.tag]) + encodelen(b) + b


if __name__ == "__main__":
    import argparse
    import pathlib

    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", nargs="+")
    args = parser.parse_args()
    for filename in args.filenames:
        with pathlib.Path(filename).open("rb") as f:
            obj = Object().from_der(f.read())
            print(obj)  # noqa: T201
