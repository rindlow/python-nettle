"""Common ASN.1 Types from assorted RFCs."""

from .asn1 import (
    OID,
    BitString,
    Boolean,
    ContextSpecific,
    GeneralizedTime,
    Integer,
    Object,
    OctetString,
    PrintableString,
    Sequence,
    Set,
    TagError,
    UTCTime,
)
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

### RFC 3279


class AlgorithmIdentifier(Sequence):
    """AlgorithmIdentifier from RFC3279."""

    algorithm: OID
    params: Object

    def __init__(self, algorithm: OID, params: Object) -> None:
        self.algorithm = algorithm
        self.params = params
        self.children = [algorithm, params]

    def _assign_children(self) -> None:
        self.algorithm = OID.from_object(self.children[0])
        self.params = self.children[1]


### RFC 4514


class AttributeTypeAndValue(Sequence):
    """AttributeTypeAndValue from RFC4514."""

    type: OID
    value: PrintableString

    def __init__(self, attribute_type: OID, value: PrintableString) -> None:
        self.type = attribute_type
        self.value = value
        self.children = [attribute_type, value]

    def __str__(self) -> str:
        return f"{ATTRIBUTE_TYPES[str(self.type)]}={self.value}"

    def _assign_children(self) -> None:
        self.type = OID.from_object(self.children[0])
        self.value = PrintableString.from_object(self.children[1])


class RelativeDistinguishedName(Set):
    """RelativeDistinguishedName from RFC4514."""

    def __str__(self) -> str:
        return "+".join(str(val) for val in self.children)

    def _assign_children(self) -> None:
        self.children = [
            AttributeTypeAndValue.from_object(atv) for atv in self.children
        ]


class Name(Sequence):
    """X501 Name from RFC4514."""

    def __str__(self) -> str:
        """Return a string representation of object."""
        return ",".join(str(rdn) for rdn in reversed(self.children))

    def _assign_children(self) -> None:
        self.children = [RelativeDistinguishedName(rdn) for rdn in self.children]


### RFC 2459


class Extension(Sequence):
    """Extension from RFC 2459."""

    extn_id: OID
    critical: Boolean
    extn_value: OctetString

    def __init__(
        self, extn_id: OID, critical: Boolean, extn_value: OctetString
    ) -> None:
        self.extn_id = extn_id
        self.critical = critical
        self.extn_value = extn_value
        self.children = [extn_id, critical, extn_value]

    def _assign_children(self) -> None:
        self.extn_id = OID.from_object(self.children[0])
        i = 1
        try:
            self.critical = Boolean.from_object(self.children[i])
            i += 1
        except TagError:
            pass
        self.extn_value = OctetString.from_object(self.children[i])


class SubjectPublicKeyInfo(Sequence):
    """SubjectPublicKeyInfo from RFC 2459."""

    algorithm: AlgorithmIdentifier
    subject_public_key: BitString

    def __init__(
        self, algorithm: AlgorithmIdentifier, subject_public_key: BitString
    ) -> None:
        self.algorithm = algorithm
        self.subject_public_key = subject_public_key
        self.children = [algorithm, subject_public_key]

    def _assign_children(self) -> None:
        self.algorithm = AlgorithmIdentifier.from_object(self.children[0])
        self.subject_public_key = BitString.from_object(self.children[1])


type Time = UTCTime | GeneralizedTime


def _time_choice(obj: Object) -> Time:
    try:
        return UTCTime.from_object(obj)
    except TagError:
        return GeneralizedTime.from_object(obj)


class Validity(Sequence):
    """Validity from RFC 2459."""

    not_before: Time
    not_after: Time

    def __init__(self, not_before: Time, not_after: Time) -> None:
        self.not_before = not_before
        self.not_after = not_after
        self.children = [not_before, not_after]

    def _assign_children(self) -> None:
        self.not_before = _time_choice(self.children[0])
        self.not_after = _time_choice(self.children[1])


class TbsCertificate(Sequence):
    """TbsCertificate from RFC 2459."""

    version: Integer
    serial_number: Integer
    signature: AlgorithmIdentifier
    issuer: Name
    validity: Validity
    subject: Name
    subject_public_key_info: SubjectPublicKeyInfo
    issuer_unique_id: BitString | None
    subject_unique_id: BitString | None
    extensions: Sequence | None

    def __init__(  # noqa: PLR0913
        self,
        version: Integer,
        serial_number: Integer,
        signature: AlgorithmIdentifier,
        issuer: Name,
        validity: Validity,
        subject: Name,
        subject_public_key_info: SubjectPublicKeyInfo,
        issuer_unique_id: BitString | None,
        subject_unique_id: BitString | None,
        extensions: Sequence | None,
    ) -> None:
        self.version = version
        self.serial_number = serial_number
        self.signature = signature
        self.issuer = issuer
        self.validity = validity
        self.subject = subject
        self.subject_public_key_info = subject_public_key_info
        self.issuer_unique_id = issuer_unique_id
        self.subject_unique_id = subject_unique_id
        self.extensions = extensions
        self.children = [
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
        ]
        if issuer_unique_id is not None:
            self.children.append(issuer_unique_id)
        if subject_unique_id is not None:
            self.children.append(subject_unique_id)
        if extensions is not None:
            self.children.append(extensions)

    def _assign_children(self) -> None:
        context = ContextSpecific.from_object(self.children[0], context=0)
        self.version = Integer.from_object(context.children[0])
        self.serial_number = Integer.from_object(self.children[1])
        self.signature = AlgorithmIdentifier.from_object(self.children[2])
        self.issuer = Name.from_object(self.children[3])
        self.validity = Validity.from_object(self.children[4])
        self.subject = Name.from_object(self.children[5])
        self.subject_public_key_info = SubjectPublicKeyInfo.from_object(
            self.children[6]
        )
        version = int(self.version)
        for child in self.children[7:]:
            if child.is_context(1):
                if version < 1:
                    raise ParseError(
                        f"issuerUniqueID not allowed in X509v{version + 1}"
                    )
                context = ContextSpecific.from_object(child, context=1)
                self.issuer_unique_id = BitString.from_object(context.children[0])
            if child.is_context(2):
                if version < 1:
                    raise ParseError(
                        f"subjectUniqueID not allowed in X509v{version + 1}"
                    )
                context = ContextSpecific.from_object(child, context=1)
                self.subject_unique_id = BitString.from_object(context.children[0])
            if child.is_context(3):
                if version < 2:
                    raise ParseError(f"extensions not allowed in X509v{version + 1}")
                context = ContextSpecific.from_object(child, context=3)
                extensions = Sequence.from_object(context.children[0])
                self.extensions = Sequence(
                    *[Extension.from_object(c) for c in extensions.children]
                )


class Certificate(Sequence):
    """Certificate from RFC 2459."""

    tbs_certificate: TbsCertificate
    signature_algorithm: AlgorithmIdentifier
    signature_value: BitString

    def __init__(
        self,
        tbs_certificate: TbsCertificate,
        signature_algorithm: AlgorithmIdentifier,
        signature_value: BitString,
    ) -> None:
        self.tbs_certificate = tbs_certificate
        self.signature_algorithm = signature_algorithm
        self.signature_value = signature_value
        self.children = [tbs_certificate, signature_algorithm, signature_value]

    def _assign_children(self) -> None:
        self.tbs_certificate = TbsCertificate.from_object(self.children[0])
        self.signature_algorithm = AlgorithmIdentifier.from_object(self.children[1])
        self.signature_value = BitString.from_object(self.children[2])


### RFC 3447


class RSAPrivateKey(Sequence):
    """RSAPrivateKey from RFC3447 (PKCS #1)."""

    version: Integer
    modulus: Integer
    public_exponent: Integer
    private_exponent: Integer
    prime1: Integer
    prime2: Integer
    exponent1: Integer
    exponent2: Integer
    coefficient: Integer

    def __init__(  # noqa: PLR0913
        self,
        version: Integer,
        modulus: Integer,
        public_exponent: Integer,
        private_exponent: Integer,
        prime1: Integer,
        prime2: Integer,
        exponent1: Integer,
        exponent2: Integer,
        coefficient: Integer,
    ) -> None:
        self.version = version
        self.modulus = modulus
        self.public_exponent = public_exponent
        self.private_exponent = private_exponent
        self.prime1 = prime1
        self.prime2 = prime2
        self.exponent1 = exponent1
        self.exponent2 = exponent2
        self.coefficient = coefficient
        self.children = [
            version,
            modulus,
            public_exponent,
            private_exponent,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
        ]

    def _assign_children(self) -> None:
        self.version = Integer.from_object(self.children[0])
        self.modulus = Integer.from_object(self.children[1])
        self.public_exponent = Integer.from_object(self.children[2])
        self.private_exponent = Integer.from_object(self.children[3])
        self.prime1 = Integer.from_object(self.children[4])
        self.prime2 = Integer.from_object(self.children[5])
        self.exponent1 = Integer.from_object(self.children[6])
        self.exponent2 = Integer.from_object(self.children[7])
        self.coefficient = Integer.from_object(self.children[8])


class RSAPublicKey(Sequence):
    """RSAPublicKey from RFC3447 (PKCS #1)."""

    modulus: Integer
    public_exponent: Integer

    def __init__(
        self,
        modulus: Integer,
        public_exponent: Integer,
    ) -> None:
        self.modulus = modulus
        self.public_exponent = public_exponent
        self.children = [modulus, public_exponent]

    def _assign_children(self) -> None:
        self.modulus = Integer.from_object(self.children[0])
        self.public_exponent = Integer.from_object(self.children[1])


### RFC 5208


class PrivateKeyInfo(Sequence):
    """PrivateKeyInfo from RFC 5208 (PKCS #8)."""

    version: Integer
    private_key_algorithm: AlgorithmIdentifier
    private_key: OctetString

    def __init__(
        self,
        version: Integer,
        private_key_algorithm: AlgorithmIdentifier,
        private_key: OctetString,
    ) -> None:
        self.version = version
        self.private_key_algorithm = private_key_algorithm
        self.private_key = private_key
        self.children = [version, private_key_algorithm, private_key]

    def _assign_children(self) -> None:
        """Validate children and populate members."""
        self.version = Integer.from_object(self.children[0])
        self.private_key_algorithm = AlgorithmIdentifier.from_object(self.children[1])
        self.private_key = OctetString.from_object(self.children[2])
