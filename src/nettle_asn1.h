typedef struct asn1object
{
  char tag_class;
  char is_constructed;
  int tag;
  int len;
  int hlen;
  int offset;
  uint8_t *data;
} asn1object;

int get_keypair_from_file (uint8_t *,
			   struct rsa_public_key *,
			   struct rsa_private_key *);
struct rsa_public_key *get_public_key_from_file (uint8_t *);
asn1object *keypair_to_der (struct rsa_public_key *, struct rsa_private_key *);
asn1object *pubkey_to_der (struct rsa_public_key *);
uint8_t *read_file (const char *);
int write_object_to_file (asn1object *, char *);

