import filecmp
import pathlib
import tempfile

import nettle.hashes
import nettle.pubkey
import nettle.pubkey.rsa
import nettle.randomness
import pytest

from .utils import read_hex_file, shex

TESTFILEPATH = pathlib.Path(__file__).with_name("testdata")


@pytest.fixture(scope="module")
def yarrow() -> nettle.randomness.Yarrow256:
    return nettle.randomness.Yarrow256()


@pytest.fixture(scope="module")
def keypair(yarrow: nettle.randomness.Yarrow256) -> nettle.pubkey.rsa.RSAKeyPair:
    return nettle.pubkey.rsa.RSAKeyPair(2048, 20, yarrow)


@pytest.mark.parametrize(
    ("algoritm", "testfile"),
    [
        (nettle.pubkey.rsa.RSAKeyPair, "rsa_priv.pem"),
        (nettle.pubkey.rsa.RSAPubKey, "rsa_pub.pem"),
        pytest.param(
            nettle.pubkey.SLHDSAKeyPair,
            "slhdsa_priv.pem",
            marks=pytest.mark.skipif(
                nettle.version < (4, 0), reason="SLH-DSA was introduced in nettle 4.0"
            ),
        ),
        pytest.param(
            nettle.pubkey.SLHDSAPubKey,
            "slhdsa_pub.pem",
            marks=pytest.mark.skipif(
                nettle.version < (4, 0), reason="SLH-DSA was introduced in nettle 4.0"
            ),
        ),
    ],
)
def test_read_write_pem(
    yarrow: nettle.randomness.Random, algoritm: nettle.pubkey.KeyPair, testfile: str
) -> None:
    filename = str(TESTFILEPATH.joinpath(testfile))
    kp = algoritm.from_file(filename, random=yarrow)
    with tempfile.NamedTemporaryFile(delete_on_close=False) as fp:
        kp.write_key_as_pem(fp.name)
        fp.close()
        assert filecmp.cmp(filename, fp.name, shallow=False)
        kp2 = algoritm.from_file(fp.name)
        assert kp2 == kp


@pytest.mark.parametrize(
    ("algoritm", "testfile"),
    [
        (nettle.pubkey.rsa.RSAKeyPair, "rsa_priv.der"),
        (nettle.pubkey.rsa.RSAPubKey, "rsa_pub.der"),
        pytest.param(
            nettle.pubkey.SLHDSAKeyPair,
            "slhdsa_priv.der",
            marks=pytest.mark.skipif(
                nettle.version < (4, 0), reason="SLH-DSA was introduced in nettle 4.0"
            ),
        ),
        pytest.param(
            nettle.pubkey.SLHDSAPubKey,
            "slhdsa_pub.der",
            marks=pytest.mark.skipif(
                nettle.version < (4, 0), reason="SLH-DSA was introduced in nettle 4.0"
            ),
        ),
    ],
)
def test_read_write_der(
    yarrow: nettle.randomness.Random, algoritm: nettle.pubkey.KeyPair, testfile: str
) -> None:
    filename = str(TESTFILEPATH.joinpath(testfile))
    kp = algoritm.from_file(filename, random=yarrow)
    with tempfile.NamedTemporaryFile(delete_on_close=False) as fp:
        kp.write_key(fp.name)
        fp.close()
        assert filecmp.cmp(filename, fp.name, shallow=False)
        kp2 = algoritm.from_file(fp.name)
        assert kp2 == kp


@pytest.mark.parametrize(
    ("algoritm", "testfile"),
    [
        (nettle.pubkey.rsa.RSAPubKey, "rsa_cert.pem"),
        (nettle.pubkey.rsa.RSAPubKey, "rsa_pub_trad.pem"),
        (nettle.pubkey.rsa.RSAKeyPair, "rsa_priv_trad.pem"),
        pytest.param(
            nettle.pubkey.SLHDSAPubKey,
            "slhdsa_cert.pem",
            marks=pytest.mark.skipif(
                nettle.version < (4, 0), reason="SLH-DSA was introduced in nettle 4.0"
            ),
        ),
    ],
)
def test_read(
    yarrow: nettle.randomness.Random, algoritm: nettle.pubkey.KeyPair, testfile: str
) -> None:
    filename = str(TESTFILEPATH.joinpath(testfile))
    assert algoritm.from_file(filename, random=yarrow) != "random string"


@pytest.mark.parametrize(
    ("algoritm", "testfile"),
    [
        (nettle.pubkey.rsa.RSAPubKey, "slhdsa_priv.pem"),
        (nettle.pubkey.rsa.RSAPubKey, "rsa_priv.pem"),
        (nettle.pubkey.rsa.RSAKeyPair, "rsa_pub.pem"),
        pytest.param(
            nettle.pubkey.SLHDSAPubKey,
            "rsa_cert.pem",
            marks=pytest.mark.skipif(
                nettle.version < (4, 0), reason="SLH-DSA was introduced in nettle 4.0"
            ),
        ),
    ],
)
def test_read_exception(
    yarrow: nettle.randomness.Random, algoritm: nettle.pubkey.KeyPair, testfile: str
) -> None:
    filename = str(TESTFILEPATH.joinpath(testfile))
    with pytest.raises(NotImplementedError):
        algoritm.from_file(filename, random=yarrow)


@pytest.mark.parametrize(
    ("algoritm", "testfile"),
    [
        (nettle.pubkey.rsa.RSAKeyPair, "broken.pem"),
        (nettle.pubkey.rsa.RSAPubKey, "broken.pem"),
        pytest.param(
            nettle.pubkey.SLHDSAKeyPair,
            "broken.pem",
            marks=pytest.mark.skipif(
                nettle.version < (4, 0), reason="SLH-DSA was introduced in nettle 4.0"
            ),
        ),
        pytest.param(
            nettle.pubkey.SLHDSAPubKey,
            "broken.pem",
            marks=pytest.mark.skipif(
                nettle.version < (4, 0), reason="SLH-DSA was introduced in nettle 4.0"
            ),
        ),
    ],
)
def test_parse_error(
    yarrow: nettle.randomness.Random, algoritm: nettle.pubkey.KeyPair, testfile: str
) -> None:
    filename = str(TESTFILEPATH.joinpath(testfile))
    with pytest.raises(nettle.ParseError):
        algoritm.from_file(filename, random=yarrow)


def test_encrypt_decrypt(keypair: nettle.pubkey.rsa.RSAKeyPair) -> None:

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


def test_sign_verify(keypair: nettle.pubkey.rsa.RSAKeyPair) -> None:

    kp = keypair
    pk = kp.public_key
    cleartext = b"Urtica dioica"

    h = nettle.hashes.SHA256()
    h.update(cleartext)
    signature = kp.sign(h)
    h2 = nettle.hashes.SHA256()
    h2.update(cleartext)
    assert pk.verify(signature, h2)
    h2.update(cleartext)
    assert kp.verify(signature, h2)
    h2.update(b"gibberish")
    assert not pk.verify(signature, h2)


def test_kp_params() -> None:
    kp = nettle.pubkey.rsa.RSAKeyPair.from_params(
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
    pk = nettle.pubkey.rsa.RSAPubKey.from_params(
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


@pytest.mark.skipif(
    nettle.version < (3, 10), reason="OAEP was introduced in nettle 3.10"
)
def test_oaep_encrypt_decrypt(keypair: nettle.pubkey.rsa.RSAKeyPair) -> None:

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


@pytest.mark.slow
@pytest.mark.skipif(
    nettle.version < (4, 0), reason="SLH-DSA was introduced in nettle 4.0"
)
@pytest.mark.parametrize(
    ("slhalg", "public", "private", "msgfile", "expectedfile"),
    [
        (
            "slh_dsa_sha2_128f",  # tcId 7
            shex("0C04FABC4FCA7F356AC36C28B99D7A1FCFEF78F38B167CA9D0AB8772910C3945"),
            shex("704555B4E5DD1B979A4C3B7A0A0E4EE241D59AE0779CAF0DF58300F21066DDA7"),
            "slh-dsa-sha2-128f-tc7.msg",
            "slh-dsa-sha2-128f-tc7.sig",
        ),
        (
            "slh_dsa_shake_128f",  # tcId 64
            shex("C9A7900E931AFBA2B52A5BC55A2DC4D12DDC9BF8E0B2ED0BDE83E674F1ECE7AA"),
            shex("0E87FF20256E0E499A53B52DF91467C01F0431C07250AFE93DE814117B5D66D3"),
            "slh-dsa-shake-128f-tc64.msg",
            "slh-dsa-shake-128f-tc64.sig",
        ),
        (
            "slh_dsa_sha2_128s",  # tcId 162
            shex("0FD12C3F990748CF9B1426413B64128EDF9242E50B9E29378BD24CAD4D547540"),
            shex("438E444071BD643C2407BD9FEB0071EC21DAA14113518133D6161EF420EE629D"),
            "slh-dsa-sha2-128s-tc162.msg",
            "slh-dsa-sha2-128s-tc162.sig",
        ),
        (
            "slh_dsa_shake_128s",  # tcId 215
            shex("DD286FF370CB50BC1B23894AA3F7025A534A788E697B94942AB845EFB753A30B"),
            shex("4738AC60C561FFBE15AB96EFFA1A09291A79332E1CA3C38B2FEF40ACA7CFE285"),
            "slh-dsa-shake-128s-tc215.msg",
            "slh-dsa-shake-128s-tc215.sig",
        ),
    ],
)
def test_slh_dsa(
    yarrow: nettle.randomness.Random,
    slhalg: str,
    public: bytes,
    private: bytes,
    msgfile: str,
    expectedfile: str,
) -> None:
    msg = read_hex_file(TESTFILEPATH.joinpath(msgfile))
    expected = read_hex_file(TESTFILEPATH.joinpath(expectedfile))

    kp = nettle.pubkey.SLHDSAKeyPair.from_params(
        key=private, pub=public, alg=slhalg, random=yarrow
    )

    pk = kp.public_key
    sig = kp.sign(msg)
    assert sig == expected
    assert pk.verify(msg, expected)
    assert kp.verify(msg, expected)


@pytest.mark.skipif(
    nettle.version < (4, 0), reason="SLH-DSA was introduced in nettle 4.0"
)
def test_slh_dsa_gen(yarrow: nettle.randomness.Random) -> None:
    msg = b"Urtica dioica"
    kp = nettle.pubkey.SLHDSAKeyPair.slh_dsa_sha2_128f(yarrow)
    sig = kp.sign(msg)
    assert kp.verify(msg, sig)
