import pathlib

import nettle.hashes
import nettle.pubkey
import nettle.randomness
import pytest

from .utils import read_hex_file, shex


@pytest.fixture(scope="module")
def yarrow() -> nettle.randomness.Yarrow256:
    return nettle.randomness.Yarrow256()


@pytest.fixture(scope="module")
def keypair(yarrow: nettle.randomness.Yarrow256) -> nettle.pubkey.RSAKeyPair:
    return nettle.pubkey.RSAKeyPair(2048, 20, yarrow)


def test_read_write(keypair: nettle.pubkey.RSAKeyPair) -> None:
    privfile = "/tmp/privkey.der"  # noqa: S108
    pubfile = "/tmp/pubkey.der"  # noqa: S108

    kp = keypair

    kp.write_key(privfile)
    kp2 = nettle.pubkey.RSAKeyPair.read_key(privfile, random=kp.random)
    assert kp == kp2
    del kp2

    pk = kp.public_key
    pk.write_key(pubfile)
    pk2 = nettle.pubkey.RSAPubKey.read_key(pubfile, random=kp.random)
    assert pk == pk2
    del pk2


def test_encrypt_decrypt(keypair: nettle.pubkey.RSAKeyPair) -> None:

    kp = keypair
    pk = kp.public_key
    cleartext = b"Urtica dioica"

    ciphertext = pk.encrypt(cleartext)
    decrypted = kp.decrypt(ciphertext)
    assert cleartext == decrypted

    ciphertext = kp.encrypt(cleartext)
    decrypted = kp.decrypt(ciphertext)
    assert cleartext == decrypted

    cleartext = b"\00" * (pk.size)
    with pytest.raises(nettle.RSAError):
        pk.encrypt(cleartext)


def test_sign_verify(keypair: nettle.pubkey.RSAKeyPair) -> None:

    kp = keypair
    pk = kp.public_key
    cleartext = b"Urtica dioica"

    h = nettle.hashes.SHA256()
    h.update(cleartext)
    signature = kp.sign(h)
    h2 = nettle.hashes.SHA256()
    h2.update(cleartext)
    assert pk.verify(signature, h2)
    h2.update(b"gibberish")
    assert not pk.verify(signature, h2)


def test_kp_params() -> None:
    kp = nettle.pubkey.RSAKeyPair.from_params(
        n=bytes.fromhex(
            "69abd505285af66536ddc7c8f027e6f0ed435d6748b16088"
            "4fd60842b3a8d7fbbd8a3c98f0cc50ae4f6a9f7dd73122cc"
            "ec8afa3f77134406f53721973115fc2d8cfbba23b145f28d"
            "84f81d3b6ae8ce1e2850580c026e809bcfbb52566ea3a3b3"
            "df7edf52971872a7e35c1451b8636d22279a8fb299368238"
            "e545fbb4cf"
        ),
        e=bytes.fromhex("0db2ad57"),
        d=bytes.fromhex(
            "3240a56f4cd0dcc24a413eb4ea5452595c83d771a1c2ba7b"
            "ec47c5b43eb4b37409bd2aa1e236dd86481eb1768811412f"
            "f8d91be3545912afb55c014cb55ceac654216af3b85d5c4f"
            "4a32894e3b5dfcde5b2875aa4dc8d9a86afd0ca92ef50d35"
            "bd09f1c47efb4c8dc631e07698d362aa4a83fd304e66d6c5"
            "468863c307"
        ),
        p=bytes.fromhex(
            "0a66399919be4b4de5a78c5ea5c85bf9aba8c013cb4a8732"
            "14557a12bd67711ebb4073fd39ad9a86f4e80253ad809e5b"
            "f2fad3bc37f6f013273c9552c9f489"
        ),
        q=bytes.fromhex(
            "0a294f069f118625f5eae2538db9338c776a298eae953329"
            "9fd1eed4eba04e82b2593bc98ba8db27de034da7daaea795"
            "2d55b07b5f9a5875d1ca5f6dcab897"
        ),
        a=bytes.fromhex(
            "011b6c48eb592eeee85d1bb35cfb6e07344ea0b5e5f03a28"
            "5b405396cbc78c5c868e961db160ba8d4b984250930cf79a"
            "1bf8a9f28963de53128aa7d690eb87"
        ),
        b=bytes.fromhex(
            "0409ecf3d2557c88214f1af5e1f17853d8b2d63782fa5628"
            "60cf579b0833b7ff5c0529f2a97c64522fa1a8878a9635ab"
            "ce56debf431bdec270b308fa5bf387"
        ),
        c=bytes.fromhex(
            "04e103ee925cb5e66653949fa5e1a462c9e65e1adcd60058"
            "e2df9607cee95fa8daec7a389a7d9afc8dd21fef9d83805a"
            "40d46f49676a2f6b2926f70c572c00"
        ),
    )
    assert kp.size == 125


def test_pk_params() -> None:
    pk = nettle.pubkey.RSAPubKey.from_params(
        n=bytes.fromhex(
            "69abd505285af66536ddc7c8f027e6f0ed435d6748b16088"
            "4fd60842b3a8d7fbbd8a3c98f0cc50ae4f6a9f7dd73122cc"
            "ec8afa3f77134406f53721973115fc2d8cfbba23b145f28d"
            "84f81d3b6ae8ce1e2850580c026e809bcfbb52566ea3a3b3"
            "df7edf52971872a7e35c1451b8636d22279a8fb299368238"
            "e545fbb4cf"
        ),
        e=bytes.fromhex("0db2ad57"),
    )
    assert pk.size == 125


def test_oaep_encrypt_decrypt(keypair: nettle.pubkey.RSAKeyPair) -> None:

    kp = keypair
    pk = kp.public_key
    cleartext = b"Urtica dioica"

    ciphertext = pk.oaep_sha256_encrypt(cleartext)
    decrypted = kp.oaep_sha256_decrypt(ciphertext)
    assert cleartext == decrypted

    ciphertext_label = pk.oaep_sha256_encrypt(cleartext, label=b"Nettle")
    decrypted = kp.oaep_sha256_decrypt(ciphertext_label, label=b"Nettle")
    assert cleartext == decrypted
    assert ciphertext != ciphertext_label

    longmessage = b"x" * 300
    with pytest.raises(nettle.RSAError):
        _ = pk.oaep_sha256_encrypt(longmessage)


def test_cert() -> None:
    certfile = "/tmp/cert.pem"  # noqa: S108
    with pathlib.Path(certfile).open("w") as f:
        f.write("""-----BEGIN CERTIFICATE-----
MIIFAjCCA+qgAwIBAgIRAIE9FoMy9cOOUjm9JU/55wswDQYJKoZIhvcNAQEFBQAw
czELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxGTAXBgNV
BAMTEFBvc2l0aXZlU1NMIENBIDIwHhcNMTMwODEyMDAwMDAwWhcNMTgwODExMjM1
OTU5WjBTMSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0ZWQxFDASBgNV
BAsTC1Bvc2l0aXZlU1NMMRgwFgYDVQQDEw9tdXBwLm5ldGNhbXAuc2UwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDH6PsKVWdTdr93gmYIkgh6MO0s10M7
1nf5Biup6pnP3EOsqSdwt2jgAFI/vGpX9q/KACDeJ8IF5THh/9Jk5dcD2/9oi8Sa
2VtZBnQGwqofwyMoUApocglCrYhWbZVBzD075h4I3io483BELl6tMD00EouWcZqz
b1moD46HklcfJoXxcV0WJuicStzAZdbL+CGj78VrrfN+2JKrHZrGAK9AjsPJ+zN8
Yn9olMsnBrBT844+YqG5uEuxx4grb02vs/mf4AMbxkelBCyKTsGYdCpBYC7oVvGy
wbYyXtpbbyNPcPSwPqiUS8urzkHt29HQ3S+Ng5ypBTrupKmFdP8ZqcGXAgMBAAGj
ggGvMIIBqzAfBgNVHSMEGDAWgBSZ5EBfaxRePgXZ3dNjVPxiuPcArDAdBgNVHQ4E
FgQUo64YW2kKHbPuy7Hio4dxxtqGLZcwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB
/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMFAGA1UdIARJMEcw
OwYLKwYBBAGyMQECAgcwLDAqBggrBgEFBQcCARYeaHR0cDovL3d3dy5wb3NpdGl2
ZXNzbC5jb20vQ1BTMAgGBmeBDAECATA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8v
Y3JsLmNvbW9kb2NhLmNvbS9Qb3NpdGl2ZVNTTENBMi5jcmwwbAYIKwYBBQUHAQEE
YDBeMDYGCCsGAQUFBzAChipodHRwOi8vY3J0LmNvbW9kb2NhLmNvbS9Qb3NpdGl2
ZVNTTENBMi5jcnQwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNv
bTAvBgNVHREEKDAmgg9tdXBwLm5ldGNhbXAuc2WCE3d3dy5tdXBwLm5ldGNhbXAu
c2UwDQYJKoZIhvcNAQEFBQADggEBAA757IeJJvDxvUcDnMRLb1ELud3UNCS9nFn5
H8m/FDOTr7jJaOO1bE5fG6SK7o71WEuT9N3EbAXtIk7lpLYWqQe4G0D8wwTVVBaS
JgJH2f0bSlkHi9g2e+fcDH/Y8XGvRIoUrvndBcmPtfCn38DushHNOr31i4rKl48n
sgoN3A1+OUpbjGR6v9crxp3zGNrNHjDonlw+WByIAB627+Vmzz8gK5/D6e7O0h99
elkmpGICXFrPJ0rPsX6w3NV1vFU8X9+bPkHG7GOh0GTMn+JqOsHI+858RQYXxg5x
aClfUZqTLvQwUMIWydXnDTuHedumUwbq40X7z9krch7Agys+KLA=
-----END CERTIFICATE-----""")
    pub = nettle.pubkey.RSAPubKey.read_key(certfile)
    assert pub.size == 256


@pytest.mark.skipif(
    nettle.version < (4, 0), reason="SLH-DSA was introduced in nettle 4.0"
)
@pytest.mark.parametrize(
    ("slhalg", "public", "private", "msg", "expected"),
    [
        (
            "slh_dsa_sha2_128f",  # tcId 7
            shex("0C04FABC4FCA7F356AC36C28B99D7A1FCFEF78F38B167CA9D0AB8772910C3945"),
            shex("704555B4E5DD1B979A4C3B7A0A0E4EE241D59AE0779CAF0DF58300F21066DDA7"),
            read_hex_file("slh-dsa-sha2-128f-tc7.msg"),
            read_hex_file("slh-dsa-sha2-128f-tc7.sig"),
        ),
        (
            "slh_dsa_shake_128f",  # tcId 64
            shex("C9A7900E931AFBA2B52A5BC55A2DC4D12DDC9BF8E0B2ED0BDE83E674F1ECE7AA"),
            shex("0E87FF20256E0E499A53B52DF91467C01F0431C07250AFE93DE814117B5D66D3"),
            read_hex_file("slh-dsa-shake-128f-tc64.msg"),
            read_hex_file("slh-dsa-shake-128f-tc64.sig"),
        ),
        (
            "slh_dsa_sha2_128s",  # tcId 162
            shex("0FD12C3F990748CF9B1426413B64128EDF9242E50B9E29378BD24CAD4D547540"),
            shex("438E444071BD643C2407BD9FEB0071EC21DAA14113518133D6161EF420EE629D"),
            read_hex_file("slh-dsa-sha2-128s-tc162.msg"),
            read_hex_file("slh-dsa-sha2-128s-tc162.sig"),
        ),
        (
            "slh_dsa_shake_128s",  # tcId 215
            shex("DD286FF370CB50BC1B23894AA3F7025A534A788E697B94942AB845EFB753A30B"),
            shex("4738AC60C561FFBE15AB96EFFA1A09291A79332E1CA3C38B2FEF40ACA7CFE285"),
            read_hex_file("slh-dsa-shake-128s-tc215.msg"),
            read_hex_file("slh-dsa-shake-128s-tc215.sig"),
        ),
    ],
)
def test_slh_dsa(
    yarrow: nettle.randomness.Random,
    slhalg: str,
    public: bytes,
    private: bytes,
    msg: bytes,
    expected: bytes,
) -> None:
    kp = nettle.pubkey.SLHDSAKeyPair.from_param(
        key=private, pub=public, alg=slhalg, random=yarrow
    )

    pk = kp.public_key
    sig = kp.sign(msg)
    assert sig == expected
    assert pk.verify(msg, expected)
