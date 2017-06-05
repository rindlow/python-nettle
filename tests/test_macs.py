from unittest import TestCase
import nettle
import sys


def SDATA(string):
    return string.encode('ascii')


def SHEX(hexstring):
    # return bytes.fromhex(hexstring) #Python 3 only. :-(
    b = bytearray()
    hexstring = ''.join(hexstring.split())
    for i in range(0, len(hexstring), 2):
        b.append(int(hexstring[i:i+2], 16))
    return bytes(b)


class MAC(TestCase):

    def _test(self, hashfunc, key, msg, digest, nonce=None):
        if nonce is None:
            h = hashfunc(key=key)
        else:
            h = hashfunc(key=key, nonce=nonce)
        h.update(msg)
        self.assertEqual(h.digest(), digest)

        h = hashfunc()
        h.set_key(key)
        if nonce:
            h.set_nonce(nonce)
        h.update(msg)
        self.assertEqual(h.digest(), digest)

    def test_hmac_sha1(self):
        self._test(nettle.hmac_sha1,
                   SHEX("0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b 0b0b0b0b"),
                   SDATA("Hi There"),
                   SHEX("b617318655057264 e28bc0b6fb378c8e f146be00"))

    def test_hmac_sha256(self):
        self._test(nettle.hmac_sha256,
                   SHEX("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
                        "0b0b0b0b"),
                   SDATA("Hi There"),
                   SHEX("b0344c61d8db38535ca8afceaf0bf12b"
                        "881dc200c9833da726e9376c2e32cff7"))

    def test_umac128(self):
        self._test(nettle.umac128,
                   key=SDATA("abcdefghijklmnop"),
                   msg=SDATA(""),
                   digest=SHEX("32fedb100c79ad58f07ff7643cc60465"),
                   nonce=SDATA("bcdefghi"))
