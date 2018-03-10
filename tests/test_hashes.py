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
        self.assertEqual(SHEX(h.hexdigest()), digest)
        self.assertEqual(hashfunc(msg).digest(), digest)

        h1 = hashfunc()
        h1.update(SDATA('a'))
        h2 = h1.copy()
        h1.update(SDATA('b'))
        h2.update(SDATA('b'))
        self.assertEqual(h1.digest(), h2.digest())
        h1.update(SDATA('c'))
        h2.update(SDATA('a'))
        self.assertNotEqual(h1.digest(), h2.digest())

    def test_gosthash94(self):
        self._test(nettle.gosthash94, SDATA("message digest"),
                   SHEX("ad4434ecb18f2c99 b60cbe59ec3d2469"
                        "582b65273f48de72 db2fde16a4889a4d"))

    def test_md2(self):
        self._test(nettle.md2, SDATA("abc"),
                   SHEX("da853b0d3f88d99b30283a69e6ded6bb"))

    def test_md4(self):
        self._test(nettle.md4, SDATA("abc"),
                   SHEX("a448017aaf21d8525fc10ae87aa6729d"))

    def test_md5(self):
        self._test(nettle.md5, SDATA("abc"),
                   SHEX("900150983cd24fb0 D6963F7D28E17F72"))

    def test_ripemd160(self):
        self._test(nettle.ripemd160, SDATA("abc"),
                   SHEX("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"))

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

    def test_sha384(self):
        self._test(nettle.sha384, SDATA("abc"),
                   SHEX("cb00753f45a35e8b b5a03d699ac65007"
                        "272c32ab0eded163 1a8b605a43ff5bed"
                        "8086072ba1e7cc23 58baeca134c825a7"))

    def test_sha512(self):
        self._test(nettle.sha512, SDATA("abc"),
                   SHEX("ddaf35a193617aba cc417349ae204131"
                        "12e6fa4e89a97ea2 0a9eeee64b55d39a"
                        "2192992a274fc1a8 36ba3c23a3feebbd"
                        "454d4423643ce80e 2a9ac94fa54ca49f"))

    def test_sha512_224(self):
        self._test(nettle.sha512_224, SDATA("abc"),
                   SHEX("4634270F 707B6A54 DAAE7530 460842E2"
                        "0E37ED26 5CEEE9A4 3E8924AA"))

    def test_sha512_256(self):
        self._test(nettle.sha512_256, SDATA("abc"),
                   SHEX("53048E26 81941EF9 9B2E29B7 6B4C7DAB"
                        "E4C2D0C6 34FC6D46 E0E2F131 07E7AF23"))

    def test_sha3_224(self):
        self._test(nettle.sha3_224, SHEX("4A4F202484512526"),
                   SHEX("01386CDD70589B3B 34941EFE16B85071"
                        "E9BA948179922044 F640868E"))

    def test_sha3_256(self):
        self._test(nettle.sha3_256, SHEX("4A4F202484512526"),
                   SHEX("BA4FB009D57A5CEB 85FC64D54E5C55A5"
                        "5854B41CC47AD152 94BC41F32165DFBA"))

    def test_sha3_384(self):
        self._test(nettle.sha3_384, SHEX("4A4F202484512526"),
                   SHEX("89DBF4C39B8FB46F DF0A6926CEC0355A"
                        "4BDBF9C6A446E140 B7C8BD08FF6F489F"
                        "205DAF8EFFE160F4 37F67491EF897C23"))

    def test_sha3_512(self):
        self._test(nettle.sha3_512, SHEX("4A4F202484512526"),
                   SHEX("150D787D6EB49670 C2A4CCD17E6CCE7A"
                        "04C1FE30FCE03D1E F2501752D92AE04C"
                        "B345FD42E51038C8 3B2B4F8FD438D1B4"
                        "B55CC588C6B91313 2F1A658FB122CB52"))
