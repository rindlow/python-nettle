from unittest import TestCase
import nettle


def SDATA(string):
    return string.encode('ascii')


def SHEX(hexstring):
    # return bytes.fromhex(hexstring) #Python 3 only. :-(
    b = bytearray()
    hexstring = ''.join(hexstring.split())
    for i in range(0, len(hexstring), 2):
        b.append(int(hexstring[i:i+2], 16))
    return bytes(b)


class Hash(TestCase):

    def _test(self, hashfunc, msg, digest):
        h = hashfunc()
        h.update(msg)
        self.assertEqual(h.digest(), digest)

    def test_sha1(self):
        self._test(nettle.sha1, SDATA(""),
                   SHEX("DA39A3EE5E6B4B0D 3255BFEF95601890 AFD80709"))

    def test_sha224(self):
        self._test(nettle.sha224, SDATA("abc"),
                   SHEX("23097d22 3405d822 8642a477 bda255b3"
                        "2aadbce4 bda0b3f7 e36c9da7"))

    def test_sha256(self):
        self._test(nettle.sha256, SDATA("abc"),
                   SHEX("ba7816bf8f01cfea 414140de5dae2223"
                        "b00361a396177a9c b410ff61f20015ad"))
