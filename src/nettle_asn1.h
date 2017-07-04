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


