# Hashes

hmacdocs = 'For an underlying hash function H, with digest size l and' \
     ' internalblock size b, HMAC-H is constructed as follows: From a' \
     ' given key k, two distinct subkeys k_i and k_o are constructed,' \
     ' both of length b. The HMAC-H of a message m is then computed as' \
     ' H(k_o | H(k_i | m)), where | denotes string concatenation. HMAC' \
     ' keys can be of any length, but it is recommended to use keys of' \
     ' length l, the digest size of the underlying hash function H.' \
     ' Keys that are longer than b are shortened to length l by hashing' \
     ' with H, so arbitrarily long keys aren\'t very useful.'

umacdocs = 'UMAC is a message authentication code based on universal' \
     ' hashing, and designed for high performance on modern processors (in' \
     ' contrast to GCM, See GCM, which is designed primarily for' \
     ' hardware performance). On processors with good integer' \
     ' multiplication performance, it can be 10 times faster than' \
     ' SHA256 and SHA512. UMAC is specified in RFC 4418. The secret key' \
     ' is always 128 bits (16 octets). The key is used as an encryption' \
     ' key for the AES block cipher. This cipher is used in counter' \
     ' mode to generate various internal subkeys needed in UMAC.' \
     ' Messages are of arbitrary size, and for each message, UMAC also' \
     ' needs a unique nonce. Nonce values must not be reused for two' \
     ' messages with the same key, but they need not be kept secret.' \
     ' The nonce must be at least one octet, and at most 16; nonces' \
     ' shorter than 16 octets are zero-padded. Nettle\'s implementation' \
     ' of UMAC increments the nonce automatically for each message, so' \
     ' explicitly setting the nonce for each message is optional. This' \
     ' auto-increment uses network byte order and it takes the length' \
     ' of the nonce into account. E.g., if the initial nonce is \\"abc\\"' \
     ' (3 octets), this value is zero-padded to 16 octets for the first' \
     ' message. For the next message, the nonce is incremented to' \
     ' \\"abd\\", and this incremented value is zero-padded to 16 octets.' \
     ' UMAC is defined in four variants, for different output sizes: 32' \
     ' bits (4 octets), 64 bits (8 octets), 96 bits (12 octets) and 128' \
     ' bits (16 octets), corresponding to different trade-offs between' \
     ' speed and security. Using a shorter output size sometimes (but' \
     ' not always!) gives the same result as using a longer output size' \
     ' and truncating the result. So it is important to use the right' \
     ' variant. For consistency with other hash and MAC functions,' \
     ' Nettle\'s _digest functions for UMAC accept a length parameter so' \
     ' that the output can be truncated to any desired size, but it is' \
     ' recommended to stick to the specified output size and select the' \
     ' umac variant corresponding to the desired size. The internal' \
     ' block size of UMAC is 1024 octets, and it also generates more' \
     ' than 1024 bytes of subkeys. This makes the size of the context' \
     ' struct quite a bit larger than other hash functions and MAC' \
     ' algorithms in Nettle.'

# Ciphers

aesdocs = 'AES is a block cipher, specified by NIST as a replacement' \
     ' for the older DES standard. The standard is the result of a' \
     ' competition between cipher designers. The winning design, also known' \
     ' as RIJNDAEL, was constructed by Joan Daemen and Vincent Rijnmen.' \
     ' Like all the AES candidates, the winning design uses a block size of' \
     ' 128 bits, or 16 octets, and three possible key-size, 128, 192 and 256' \
     ' bits (16, 24 and 32 octets) being the allowed key sizes. It does not' \
     ' have any weak keys.'

camelliadocs = 'Camellia is a block cipher developed by Mitsubishi and' \
     ' Nippon Telegraph and Telephone Corporation, described in RFC3713. It' \
     ' is recommended by some Japanese and European authorities as an' \
     ' alternative to AES, and it is one of the selected algorithms in' \
     ' the New European Schemes for Signatures, Integrity and' \
     ' Encryption (NESSIE) project. The algorithm is patented. The' \
     ' implementation in Nettle is derived from the implementation' \
     ' released by NTT under the GNU LGPL (v2.1 or later), and relies' \
     ' on the implicit patent license of the LGPL. There is also a' \
     ' statement of royalty-free licensing for Camellia at' \
     ' http://www.ntt.co.jp/news/news01e/0104/010417.html, but this' \
     ' statement has some limitations which seem problematic for free' \
     ' software.' \
     ' Camellia uses a the same block size and key sizes as AES: The block' \
     ' size is 128 bits (16 octets), and the supported key sizes are' \
     ' 128, 192, and 256 bits. The variants with 192 and 256 bit keys' \
     ' are identical, except for the key setup.'

arcfourdocs = 'ARCFOUR is a stream cipher, also known under the trade marked' \
     'name RC4, and it is one of the fastest ciphers around. A' \
     ' problem is that the key setup of ARCFOUR is quite weak, you should' \
     ' never use keys with structure, keys that are ordinary' \
     ' passwords, or sequences of keys like "secret:1", "secret:2"' \
     ' .... If you have keys that don\'t look like random bit strings,' \
     ' and you want to use ARCFOUR, always hash the key before feeding' \
     ' it to ARCFOUR. Furthermore, the initial bytes of the generated' \
     ' key stream leak information about the key; for this reason, it' \
     ' is recommended to discard the first 512 bytes of the key' \
     ' stream.'

serpentdocs = 'SERPENT is one of the AES finalists, designed by Ross' \
     ' Anderson, Eli Biham and Lars Knudsen. Thus, the interface and' \
     ' properties are similar to AES\'. One peculiarity is that it is' \
     ' quite pointless to use it with anything but the maximum key size,' \
     ' smaller keys are just padded to larger ones.'

twofishdocs = 'Another AES finalist, this one designed by Bruce Schneier ' \
     'and others.'
