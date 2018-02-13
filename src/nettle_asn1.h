/* nettle_asn1.h

   Copyright (C) 2017, 2018 Henrik Rindlöw

   This file is part of python-nettle.

   Python-nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   Python-nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

int keypair_from_pkcs1 (uint8_t *,
			struct rsa_public_key *,
			struct rsa_private_key *);
int keypair_from_pkcs8 (uint8_t *,
			struct rsa_public_key *,
			struct rsa_private_key *);
int keypair_to_pkcs1 (struct rsa_public_key *,
		      struct rsa_private_key *,
		      uint8_t **, int *);
struct rsa_public_key *pubkey_from_cert (uint8_t *);
struct rsa_public_key *pubkey_from_pkcs1 (uint8_t *);
struct rsa_public_key *pubkey_from_pkcs8 (uint8_t *);
int pubkey_to_pkcs8 (struct rsa_public_key *, uint8_t **, int *);


