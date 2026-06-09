"""Test ASN.1 Module."""

import pytest
from nettle import asn1


@pytest.mark.parametrize(
    ("der", "expected"),
    [
        ("0101FF", True),
        ("010100", False),
    ],
)
def test_boolean_from_der(der: str, expected: bool) -> None:  # noqa: FBT001
    """Test deserializing boolean objects."""
    obj = asn1.Boolean.from_der(bytes.fromhex(der))
    assert bool(obj) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, "0101FF"),
        (False, "010100"),
    ],
)
def test_boolean_to_der(value: bool, expected: str) -> None:  # noqa: FBT001
    """Test serializing boolean objects."""
    assert asn1.Boolean(value).to_der() == bytes.fromhex(expected)


def test_boolean_exceptions() -> None:
    with pytest.raises(asn1.TagError):
        asn1.Boolean.from_der(bytes.fromhex("020100"))
    with pytest.raises(asn1.ParseError):
        asn1.Boolean.from_der(bytes.fromhex("0100"))


@pytest.mark.parametrize(
    ("der", "expected"),
    [
        ("020100", 0),
        ("020111", 17),
        ("0202FF7F", -129),
        ("020180", -128),
        ("0201FF", -1),
        ("020200FF", 255),
        ("02020100", 256),
    ],
)
def test_integer_from_der(der: str, expected: int) -> None:
    """Test deserializing integer objects."""
    obj = asn1.Integer.from_der(bytes.fromhex(der))
    assert int(obj) == expected
    with pytest.raises(asn1.TagError):
        asn1.Integer.from_der(bytes.fromhex("010100"))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (-129, "0202FF7F"),
        (-128, "020180"),
        (-1, "0201FF"),
        (0, "020100"),
        (17, "020111"),
        (255, "020200FF"),
        (256, "02020100"),
    ],
)
def test_integer_to_der(value: int, expected: str) -> None:
    """Test serializing integer objects."""
    i = asn1.Integer(value)
    assert i.to_der() == bytes.fromhex(expected)
    bitlen = value.bit_length()
    assert bytes(i) == value.to_bytes(bitlen // 8 + 1, signed=True)


def test_integer_exceptions() -> None:
    with pytest.raises(asn1.TagError):
        asn1.Integer.from_der(bytes.fromhex("010100"))
    with pytest.raises(asn1.ParseError):
        asn1.Integer.from_der(bytes.fromhex("0201"))


def test_bit_string_from_der() -> None:
    """Test bit string objects."""
    obj = asn1.BitString.from_der(bytes.fromhex("0304066e5dc0"))
    assert bytes(obj) == bytes.fromhex("6e5dc0")
    assert obj.unused_bits == 6


def test_bit_string_to_der() -> None:
    """Test serializing bit string objects."""
    assert asn1.BitString(
        bytes.fromhex("6e5dc0"), unused_bits=6
    ).to_der() == bytes.fromhex("0304066e5dc0")

    assert asn1.BitString(bytes(b"\0" * 128)).to_der()[:4] == bytes.fromhex("03818100")
    assert asn1.BitString(bytes(b"\0" * 256)).to_der()[:4] == bytes.fromhex("03820101")


def test_octet_string_from_der() -> None:
    """Test octet string objects."""
    obj = asn1.OctetString.from_der(bytes.fromhex("0404066e5dc0"))
    assert bytes(obj) == bytes.fromhex("066e5dc0")


def test_octet_string_to_der() -> None:
    """Test serializing bit string objects."""
    assert asn1.OctetString(bytes.fromhex("066e5dc0")).to_der() == bytes.fromhex(
        "0404066e5dc0"
    )


def test_null_from_der() -> None:
    """Test null objects."""
    obj = asn1.Null.from_der(bytes.fromhex("0500"))
    assert obj.value is None


def test_null_to_der() -> None:
    """Test serializing null objects."""
    assert asn1.Null().to_der() == bytes.fromhex("0500")


def test_oid_from_der() -> None:
    """Test oid objects."""
    obj = asn1.OID.from_der(bytes.fromhex("06092a864886f70d01010b"))
    assert str(obj) == "1.2.840.113549.1.1.11"


def test_oid_to_der() -> None:
    """Test serializing oid objects."""
    assert asn1.OID("1.2.840.113549.1.1.11").to_der() == bytes.fromhex(
        "06092a864886f70d01010b"
    )


class ThreeInts(asn1.Sequence):
    a: asn1.Integer
    b: asn1.Integer
    c: asn1.Integer

    def __init__(self, a: asn1.Integer, b: asn1.Integer, c: asn1.Integer) -> None:
        self.a = a
        self.b = b
        self.c = c
        self.children = [a, b, c]

    def _assign_children(self) -> None:
        self.a = asn1.Integer.from_object(self.children[0])
        self.b = asn1.Integer.from_object(self.children[1])
        self.c = asn1.Integer.from_object(self.children[2])


def test_sequence_from_der() -> None:
    """Test sequence objects."""
    obj = ThreeInts.from_der(bytes.fromhex("3009020107020108020109"))
    assert int(obj.a) == 7
    assert int(obj.b) == 8
    assert int(obj.c) == 9


def test_sequence_to_der() -> None:
    """Test serializing sequence objects."""
    assert asn1.Sequence(
        *(asn1.Integer(i) for i in range(7, 10))
    ).to_der() == bytes.fromhex("3009020107020108020109")
