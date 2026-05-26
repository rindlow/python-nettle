import nettle
import pytest

from .utils import shex


@pytest.mark.parametrize(
    ("cls", "seed", "expected"),
    [
        (
            nettle.Yarrow256,
            shex("0000000000000000000000000000000000000000000000000000000000000000"),
            shex("200fe7972e93822621682027def98729"),
        ),
        (
            nettle.DRBG_CTR_AES256,
            shex(
                "0000000000000000000000000000000000000000000000000000000000000000"
                "00000000000000000000000000000000"
            ),
            shex("91618fe99a8f9420497b246f735b27a0"),
        ),
    ],
)
def test_random(cls: type[nettle.Random], seed: bytes, expected: bytes) -> None:
    rnd = cls(seed)
    assert rnd.random(16) == expected

    with pytest.raises(nettle.ShortSeedError):
        _ = cls(seed[:-1])

    rnd = cls()
    assert len(rnd.random(2)) == 2
