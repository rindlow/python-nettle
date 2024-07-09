from unittest import TestCase
import nettle


def SDATA(string: str) -> bytes:
    return string.encode('ascii')


def SHEX(hexstring: str) -> bytes:
    # return bytes.fromhex(hexstring) #Python 3 only. :-(
    b = bytearray()
    hexstring = ''.join(hexstring.split())
    for i in range(0, len(hexstring), 2):
        b.append(int(hexstring[i:i + 2], 16))
    return bytes(b)


class Hash(TestCase):

    def _test(self, hashfunc: type[nettle.DigestableHash],
              msg: bytes, digest: bytes) -> None:
        h: nettle.DigestableHash = hashfunc()
        h.update(msg)
        self.assertEqual(h.digest(), digest)
        h.update(msg)
        self.assertEqual(SHEX(h.hexdigest()), digest)
        h.update(msg)
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

    def _test_shake(self, hashfunc: type[nettle.ShakeableHash],
                    msg: bytes, digest: bytes) -> None:
        h: nettle.ShakeableHash = hashfunc()
        h.update(msg)
        self.assertEqual(h.shake(512), digest)
        h.update(msg)
        self.assertEqual(h.shake_output(512), digest)

    def test_gosthash94(self) -> None:
        self._test(nettle.gosthash94, SDATA("message digest"),
                   SHEX("ad4434ecb18f2c99 b60cbe59ec3d2469"
                        "582b65273f48de72 db2fde16a4889a4d"))

    def test_md2(self) -> None:
        self._test(nettle.md2, SDATA("abc"),
                   SHEX("da853b0d3f88d99b30283a69e6ded6bb"))

    def test_md4(self) -> None:
        self._test(nettle.md4, SDATA("abc"),
                   SHEX("a448017aaf21d8525fc10ae87aa6729d"))

    def test_md5(self) -> None:
        self._test(nettle.md5, SDATA("abc"),
                   SHEX("900150983cd24fb0 D6963F7D28E17F72"))

    def test_ripemd160(self) -> None:
        self._test(nettle.ripemd160, SDATA("abc"),
                   SHEX("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"))

    def test_sha1(self) -> None:
        self._test(nettle.sha1, SDATA(""),
                   SHEX("DA39A3EE5E6B4B0D 3255BFEF95601890 AFD80709"))

    def test_sha224(self) -> None:
        self._test(nettle.sha224, SDATA("abc"),
                   SHEX("23097d22 3405d822 8642a477 bda255b3"
                        "2aadbce4 bda0b3f7 e36c9da7"))

    def test_sha256(self) -> None:
        self._test(nettle.sha256, SDATA("abc"),
                   SHEX("ba7816bf8f01cfea 414140de5dae2223"
                        "b00361a396177a9c b410ff61f20015ad"))

    def test_sha384(self) -> None:
        self._test(nettle.sha384, SDATA("abc"),
                   SHEX("cb00753f45a35e8b b5a03d699ac65007"
                        "272c32ab0eded163 1a8b605a43ff5bed"
                        "8086072ba1e7cc23 58baeca134c825a7"))

    def test_sha512(self) -> None:
        self._test(nettle.sha512, SDATA("abc"),
                   SHEX("ddaf35a193617aba cc417349ae204131"
                        "12e6fa4e89a97ea2 0a9eeee64b55d39a"
                        "2192992a274fc1a8 36ba3c23a3feebbd"
                        "454d4423643ce80e 2a9ac94fa54ca49f"))

    def test_sha512_224(self) -> None:
        self._test(nettle.sha512_224, SDATA("abc"),
                   SHEX("4634270F 707B6A54 DAAE7530 460842E2"
                        "0E37ED26 5CEEE9A4 3E8924AA"))

    def test_sha512_256(self) -> None:
        self._test(nettle.sha512_256, SDATA("abc"),
                   SHEX("53048E26 81941EF9 9B2E29B7 6B4C7DAB"
                        "E4C2D0C6 34FC6D46 E0E2F131 07E7AF23"))

    def test_sha3_224(self) -> None:
        self._test(nettle.sha3_224, SHEX("4A4F202484512526"),
                   SHEX("01386CDD70589B3B 34941EFE16B85071"
                        "E9BA948179922044 F640868E"))

    def test_sha3_256(self) -> None:
        self._test(nettle.sha3_256, SHEX("4A4F202484512526"),
                   SHEX("BA4FB009D57A5CEB 85FC64D54E5C55A5"
                        "5854B41CC47AD152 94BC41F32165DFBA"))

    def test_sha3_384(self) -> None:
        self._test(nettle.sha3_384, SHEX("4A4F202484512526"),
                   SHEX("89DBF4C39B8FB46F DF0A6926CEC0355A"
                        "4BDBF9C6A446E140 B7C8BD08FF6F489F"
                        "205DAF8EFFE160F4 37F67491EF897C23"))

    def test_sha3_512(self) -> None:
        self._test(nettle.sha3_512, SHEX("4A4F202484512526"),
                   SHEX("150D787D6EB49670 C2A4CCD17E6CCE7A"
                        "04C1FE30FCE03D1E F2501752D92AE04C"
                        "B345FD42E51038C8 3B2B4F8FD438D1B4"
                        "B55CC588C6B91313 2F1A658FB122CB52"))

    def test_streebog512(self) -> None:
        self._test(nettle.streebog512,
                   SDATA("0123456789012345678901234567890"
                         "12345678901234567890123456789012"),
                   SHEX("1b54d01a4af5b9d5 cc3d86d68d285462"
                        "b19abc2475222f35 c085122be4ba1ffa"
                        "00ad30f8767b3a82 384c6574f024c311"
                        "e2a481332b08ef7f 41797891c1646f48"))

    def test_streebog256(self) -> None:
        self._test(nettle.streebog256,
                   SDATA("0123456789012345678901234567890"
                         "12345678901234567890123456789012"),
                   SHEX("9d151eefd8590b89 daa6ba6cb74af927"
                        "5dd051026bb149a4 52fd84e5e57b5500"))

    def test_sm3(self) -> None:
        self._test(nettle.sm3,
                   SDATA("abc"),
                   SHEX("66c7f0f462eeedd9 d1f2d46bdc10e4e2"
                        "4167c4875cf2f7a2 297da02b8f4ba8e0"))

    def test_shake128(self) -> None:
        self._test_shake(nettle.sha3_128,
                         SHEX("52A608AB21CCDD8A4457A57EDE782176"),
                         SHEX("3A0FACA70C9D2B81D1064D429EA3B05A"
                              "D27366F64985379DDD75BC73D6A83810"
                              "45C2AE2E9C723462EE09EFBB1C2A8ED7"
                              "A0729D0D9B20F03BBCF55A86859ECBE8"
                              "0C8CAB60BAB4C5D063DEA224E825E386"
                              "42124EA705327E075B61D08E0B49DC18"
                              "4C5194292BB4A797CD24D924CC64816B"
                              "F911FBF4985130A59D68FF0673CC8C4A"
                              "390AD593BEBF16419FF464ECB3FC78C1"
                              "60B6DB9F755A5FAA7A9365B58CE7F904"
                              "65AF960C48B771699E0EB227F5370387"
                              "E6248E17EE192007128EE7AD3D94BB9A"
                              "2193BBD4618AFB3A399CB2016ECD5F9E"
                              "41AF10701FF1915A6E091F44F193B0F7"
                              "29CC4AF5FECF683B1C7DD2644D7458C4"
                              "5FFD635EEB85C79E241C1F4869CDA9E7"
                              "7E80F7B878C24E9AF77D22D8C7C0C406"
                              "C8AAF50F57BAB68FC6C3A20274B6BC35"
                              "3E6D60DA40E8369139B4508DAE96DBA1"
                              "2DCA9D80A19041A3798B252FD24BF2BE"
                              "64035CDA6D95D6E570EA868EB8808193"
                              "B3792897A2147396A47D27C81D40FF4B"
                              "F9212AB239D7A789D8CDD545A98B447F"
                              "6ABBFF4BF6FE631CF2483881E933C1E6"
                              "2A21BEC503A6EA60F3B179F9CA6852DA"
                              "ABA4CED7ADE5E35E960463FA4C3A32F4"
                              "C580F03CD2E45F10E32507FB2880827F"
                              "56BFC5030A4CA94635EDB134580715A2"
                              "3C87D755FD91B1566D1A471F310EDB2C"
                              "12AA11F2D280683F43155D67E2EC04EC"
                              "2CB2CEE53A4D00F77AA73DCD6CAD61D1"
                              "AB7C30A627CC75F83D48BDF9A76AB456"))

    def test_shake256(self) -> None:
        self._test_shake(nettle.sha3_256,
                         SHEX("52A608AB21CCDD8A4457A57EDE782176"),
                         SHEX("57119C4507F975AD0E9EA4F1166E5F9B"
                              "590BF2671AAEB41D130D2C570BAFC579"
                              "B0B9EC485CC736A0A848BBC886CBAA79"
                              "FFCD067CE64B3B410741AB011C544225"
                              "68089405BF1E8DDD9E3BCEFE1A713DDA"
                              "18CC2B73FDE0EB323FA7518DE2808C87"
                              "5A6C55111BE3E0CD20663B794048F5FF"
                              "44638EF871FBA0F4C2ED41A96D362160"
                              "6740935E9EA1ABEFE15A1A3BD55C8AE6"
                              "B2C021CC772B34DA219115C8F6072A09"
                              "F2B718E26ECD2538E5F12068F577ED7D"
                              "03A2BBCC7CA7DB81D2CBAEF2AC8F33B1"
                              "355798576CD3545B9DC792FDBB9C8D1C"
                              "123EE0407C6328E09103FA6CE1B4DC9F"
                              "FB0BE7236DAB3ABD29E704D0C352C524"
                              "FAC14E12FB61929D98DED973D7E8785A"
                              "8ACF52AF56C01CE62AD93660C93B683F"
                              "C22088D7302F72D0DAE54553B0C3E6DA"
                              "7C498BEB3AA46E7459779A1B0E1FB195"
                              "56A71635B404C0BBBF3F34536F2776FA"
                              "12206513FBB1F2A11CE9683460D22778"
                              "867ABA7335210D817B720B3D8A8C4824"
                              "3D128EA2A4BA8996D160351194C0AD39"
                              "88ED0AC5ED61C1F576A33C914C2BEBEE"
                              "0EEBE55878E2B43A51E510251068E3C0"
                              "F7C7292189573EB6AF979CDAEBA8B8E3"
                              "59E6B632BABAFE3528773CDD4A1861B7"
                              "AB2532113F2B259D45598A76D54C739D"
                              "C2F4AF2700F3B5CF22431ED9F73D53CA"
                              "F41D134F5CC67ECF8F99549C091CA669"
                              "7FF20E08BF6AE9B6BE74BC77F26DB50D"
                              "25F48E67A94DD705521F02D3CBD5FD56"))
