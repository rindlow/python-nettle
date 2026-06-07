"""Common ASN.1 Types from assorted RFCs."""

from .asn1 import Sequence, TagError
from .exceptions import ParseError

ATTRIBUTE_TYPES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "0.9.2342.19200300.100.1.1": "UID",
    "0.9.2342.19200300.100.1.25": "DC",
}

OID_PKCS7_SIGNEDDATA = "1.2.840.113549.1.7.2"
OID_ID_CT_TSTINFO = "1.2.840.113549.1.9.16.1.4"

### RFC 2459


class Certificate(Sequence):
    """Certificate from RFC 2459."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.tbs_certificate = TbsCertificate(self.child(0))
        self.signature_algorithm = AlgorithmIdentifier(self.child(1))
        self.signature_value = self.child(2).bit_string()


class Extension(Sequence):
    """Extension from RFC 2459."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.extn_id = self.child(0).oid()
        self.critical = self.child(1).boolean()
        self.extn_value = self.child(2).octet_string()


class SubjectPublicKeyInfo(Sequence):
    """SubjectPublicKeyInfo from RFC 2459."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.algorithm = AlgorithmIdentifier(self.child(0))
        self.subject_public_key = self.child(1).bit_string()


class TbsCertificate(Sequence):
    """TbsCertificate from RFC 2459."""

    def validate(self) -> None:
        """Validate children and populate members."""
        context = self.child(0)
        if not context.is_context(0) and context.num_children() == 1:
            raise ParseError("Version not context [0]")
        self.version = context.child(0).integer() + 1
        self.serial_number = self.child(1).integer()
        self.signature = AlgorithmIdentifier(self.child(2))
        self.issuer = Name(self.child(3))
        self.validity = Validity(self.child(4))
        self.subject = Name(self.child(5))
        # ignore self.subjectPublicKeyInfo (6) for now
        for child in self.children[7:]:
            if child.is_context(1):
                if self.version < 2:
                    raise ParseError("issuerUniqueID in early version")
                self.issuer_unique_id = child.bit_string()
            if child.is_context(2):
                if self.version < 2:
                    raise ParseError("subjectUniqueID in early version")
                self.subject_unique_id = child.bit_string()
            if child.is_context(3):
                if self.version < 3:
                    raise ParseError("extensions in early version")
                self.extensions = [Extension(c) for c in child.children]


class Time(Sequence):
    """Time from RFC 2459."""

    def validate(self) -> None:
        """Validate children and populate members."""
        try:
            self.time = self.utctime()
        except TagError:
            self.time = self.generalized_time()


class Validity(Sequence):
    """Validity from RFC 2459."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.not_before = Time(self.child(0))
        self.not_after = Time(self.child(1))


### RFC 2510


class PKIFreeText(Sequence):
    """PKIFreeText from RFC 2510."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.strings = [s.utf8_string() for s in self.sequence()]

    def __str__(self) -> str:
        """Return a string representation of object."""
        return "\n".join(self.strings)


class PKIStatusInfo(Sequence):
    """PKI Status from RFC 2510."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.status = self.child(0).integer()
        for child in self.sequence()[1:]:
            if child.is_sequence():
                self.status_string = PKIFreeText(child)
            if child.is_bit_string():
                self.fail_info = child.bit_string()


### RFC 3279


class AlgorithmIdentifier(Sequence):
    """AlgorithmIdentifier from RFC3279."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.algorithm = self.child(0).oid()
        self.params = self.child(1)


### RFC 3447


class RSAPrivateKey(Sequence):
    """RSAPrivateKey from RFC3447 (PKCS #1)."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.version = self.child(0).integer()
        self.modulus = self.child(1).integer()
        self.public_exponent = self.child(2).integer()
        self.private_exponent = self.child(3).integer()
        self.prime1 = self.child(4).integer()
        self.prime2 = self.child(5).integer()
        self.exponent1 = self.child(6).integer()
        self.exponent2 = self.child(7).integer()
        self.coefficient = self.child(8).integer()


class RSAPublicKey(Sequence):
    """RSAPublicKey from RFC3447 (PKCS #1)."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.modulus = self.child(0).integer()
        self.public_exponent = self.child(1).integer()


### RFC 4514


class AttributeTypeAndValue(Sequence):
    """AttributeTypeAndValue from RFC4514."""

    def __str__(self) -> str:
        """Return a string representation of object."""
        return f"{ATTRIBUTE_TYPES[self.type]}={self.value}"

    def validate(self) -> None:
        """Validate children and populate members."""
        self.type = self.child(0).oid()
        self.value = self.child(1).printable_string()


class Name(Sequence):
    """X501 Name from RFC4514."""

    def __str__(self) -> str:
        """Return a string representation of object."""
        return ",".join(str(rdn) for rdn in reversed(self.rdn_sequence))

    def validate(self) -> None:
        """Validate children and populate members."""
        self.rdn_sequence = [RelativeDistinguishedName(rdn) for rdn in self.sequence()]


class RelativeDistinguishedName(Sequence):
    """RelativeDistinguishedName from RFC4514."""

    def __str__(self) -> str:
        """Return a string representation of object."""
        return "+".join(str(val) for val in self.value)

    def validate(self) -> None:
        """Validate children and populate members."""
        self.value = [AttributeTypeAndValue(atv) for atv in self.set()]


### RFC 5208


class PrivateKeyInfo(Sequence):
    """PrivateKeyInfo from RFC 5208 (PKCS #8)."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.version = self.child(0).integer()
        self.private_key_algorithm = AlgorithmIdentifier(self.child(1))
        self.private_key = self.child(2).octet_string()


### RFC 5652


class Attribute(Sequence):
    """Attribute from RFC 5652."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.type = self.child(0).oid()
        self.values = self.child(1).set()


class EncapsulatedContentInfo(Sequence):
    """EncapsulatedContentInfo from RFC5652."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.e_content_type = self.child(0).oid()
        context = self.child(1)
        if not context.is_context(0):
            raise ParseError("eContent not context[0]")

        self.e_content = context.child(0).octet_string()


class IssuerAndSerialNumber(Sequence):
    """IssuerAndSerialNumber from RFC 5652."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.issuer = Name(self.child(0))
        self.serial_number = self.child(1).integer()


class SignedData(Sequence):
    """SignedData from RFC5652."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.version = self.child(0).integer()
        self.digest_algorithms: list[Sequence] = self.child(1).set()
        self.encap_content_info = EncapsulatedContentInfo(self.child(2))
        self.certificates: list[Sequence] = []
        self.crls: list[Sequence] = []
        self.signer_infos: list[SignerInfo] = []

        for child in self.sequence()[3:]:
            if child.is_context(0):
                self.certificates = child.set()
            if child.is_context(1):
                self.crls = child.set()
            if child.is_set():
                self.signer_infos = [SignerInfo(si) for si in child.set()]


class SignerInfo(Sequence):
    """SignerInfo from RFC 5652."""

    def validate(self) -> None:
        """Validate children and populate members."""
        self.version = self.child(0).integer()
        if self.version != 1:
            raise NotImplementedError
        self.sid = IssuerAndSerialNumber(self.child(1))
        self.digest_algorithm = self.child(2)
        n = 3
        if self.child(n).is_context(0):
            self.signed_attributes = [
                Attribute(attr) for attr in self.child(n).constructed()
            ]
            n += 1
        self.signature_algorithm = AlgorithmIdentifier(self.child(n))
        self.signature = self.child(n + 1).octet_string()
