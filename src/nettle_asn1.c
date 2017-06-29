#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <Python.h>
#include <gmp.h>
#include <nettle/rsa.h>
#include "nettle.h"
#include "nettle_asn1.h"

const char *base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "abcdefghijklmnopqrstuvwxyz0123456789+/=";

uint8_t *
base64decode (char *in)
{
  uint8_t *out;
  size_t inlen;
  int work, n, o;
  char *idx;

  inlen = strlen ((char *) in);
  out = malloc (inlen * 3 / 4);
  o = 0;
  work = 0;
  n = 0;
  for (size_t i = 0; i < inlen; i++)
    {
      idx = index (base64chars, in[i]);
      if (idx != NULL)
	{
	  work <<= 6;
	  work |= ((idx - base64chars) & 0x3f);
	  n++;
	  if (n == 4)
	    {
	      for (int j = 16; j >= 0; j -= 8)
		{
		  out[o++] = (work >> j) & 0xff;
		}
	      work = 0;
	      n = 0;
	    }
	}
    }
  return out;
}

uint8_t *
read_file (const char *filename)
{
  FILE *f;
  char *buf, *start, *end;
  uint8_t *der;
  long len;
  if ((f = fopen (filename, "r")) == NULL)
    {
      perror ("fopen failed");
      return NULL;
    }
  if (fseek (f, 0, SEEK_END) < 0)
    {
      perror ("fseek to end failed");
      return NULL;
    }
  if ((len = ftell (f)) < 0)
    {
      perror ("ftell failed");
      return NULL;
    }
  if (fseek (f, 0, SEEK_SET) < 0)
    {
      perror ("fseek to start failed");
      return NULL;
    }
  if ((buf = malloc (len + 1)) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }
  if (fread (buf, len, 1, f) < 1)
    {
      perror ("fread failed");
      return NULL;
    }
  buf[len] = '\0';

  if (strstr (buf, "-----BEGIN") == NULL)
    return (uint8_t *) buf;

  start = strchr (buf, '\n');
  end = strchr (start, '-');
  *end = '\0';
  der = base64decode (start);
  free (buf);
  fclose(f);
  return der;
}

asn1object *
parse_header (uint8_t * data, int offset)
{
  asn1object *h;
  uint8_t b;
  int i = 0, lenlen;

  // Parse identifier
  h = malloc (sizeof (asn1object));
  b = data[i++];

  h->tag_class = b >> 6;
  h->is_constructed = (b >> 5) & 0x01;
  if ((b & 0x1f) != 0x1f)
    {
      h->tag = b & 0x1f;
    }
  else
    {
      h->tag = 0;
      do
	{
	  b = data[i++];
	  h->tag <<= 7;
	  h->tag = b & 0x7f;
	}
      while (b & 0x80);
    }

  // Parse length
  b = data[i++];
  if ((b & 0x80) == 0)
    {
      h->len = b;
    }
  else
    {
      lenlen = b & 0x7f;
      if (lenlen > 4)
	{
	  // We should never get a length that won't fit in an int
	  return NULL;
	}
      h->len = 0;
      for (int j = 0; j < lenlen; j++)
	{
	  h->len <<= 8;
	  h->len |= data[i++];
	}
    }
  h->hlen = i;
  h->offset = offset;
  if ((h->data = malloc (h->len)) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }

  memcpy (h->data, &data[i], h->len);

  return h;
}

void
free_asn1object (asn1object * obj)
{
  free (obj->data);
  free (obj);
}

asn1object *
root_object (uint8_t * data)
{
  return parse_header (data, 0);
}

asn1object *
first_child (struct asn1object * o)
{
  struct asn1object *ret;
  ret = parse_header (o->data, o->offset + o->hlen);
  return ret;
}

asn1object *
next_child (struct asn1object * p, struct asn1object * o)
{
  struct asn1object *ret;
  int offset = o->offset + o->hlen + o->len;
  ret = parse_header (&p->data[offset - p->offset - p->hlen], offset);
  return ret;
}

asn1object *
assert_integer (asn1object * o)
{
  if (o->tag_class == 0 && o->is_constructed == 0 && o->tag == 2)
    {
      return o;
    }
  PyErr_Format (ASN1Error, "ASN.1: No INTEGER found at byte %d\n", o->offset);
  return NULL;
}

asn1object *
assert_bitstring (asn1object * o)
{
  uint8_t *data;
  if (o->tag_class == 0 && o->is_constructed == 0 && o->tag == 3)
    {
      if (o->data[0] != 0)
	{
	  PyErr_Format (ASN1Error,
		   "ASN.1: Bitstring with non octet bits found at byte %d\n",
		   o->offset);
	  return NULL;
	}
      if ((data = malloc (o->len - 1)) == NULL)
	{
	  PyErr_Format(PyExc_MemoryError, "malloc failed");
	  return NULL;
	}
      memcpy (data, &o->data[1], o->len - 1);
      free (o->data);
      o->data = data;
      o->len--;
      return o;
    }
  PyErr_Format (ASN1Error, "ASN.1: No INTEGER found at byte %d\n", o->offset);
  return NULL;
}

asn1object *
assert_sequence (asn1object * o)
{
  if (o->tag_class == 0 && o->is_constructed == 1 && o->tag == 16)
    {
      return o;
    }
  PyErr_Format (ASN1Error, "ASN.1: No SEQUENCE found at byte %d\n", o->offset);
  return NULL;
}

asn1object *
assert_context0 (asn1object * o)
{
  if (o->tag_class == 2 && o->is_constructed == 1 && o->tag == 0)
    {
      return o;
    }
  PyErr_Format (ASN1Error, "ASN.1: No [%d] found at byte %d\n",
		o->tag, o->offset);
  return NULL;
}

// char *
// bytes_to_str (uint8_t * buf, int len)
// {
//   char *str;
//   if ((str = malloc (len * 2 + 1)) == NULL)
//     {
//       PyErr_Format(PyExc_MemoryError, "malloc failed");
//       return NULL;
//     }
//   char *ptr = str;
//   for (int i = 0; i < len; i++)
//     {
//       snprintf (ptr, 3, "%02X", buf[i]);
//       ptr += 2;
//     }
//   return str;
// }
// 
// uint8_t *
// str_to_bytes (char *buf, int *len)
// {
//   uint8_t *bytes;
//   int itmp, i, j, odd = 0, negative = 0, buflen;
//   char tmp[3];
//   tmp[2] = 0;
//   buflen = (int) strlen (buf);
//   *len = buflen / 2;
//   if (buflen % 2 == 1)
//     {
//       (*len)++;
//       odd = 1;
//     }
//   else if (buf[0] < '0' || buf[0] > '7')
//     {
//       (*len)++;
//       negative = 1;
//     }
// 
//   if ((bytes = malloc (*len)) == NULL)
//     {
//       PyErr_Format(PyExc_MemoryError, "malloc failed");
//       return NULL;
//     }
//   i = 0;
//   j = 0;
//   if (negative)
//     {
//       bytes[j++] = 0;
//     }
//   while (i < buflen)
//     {
//       if (odd && i == 0)
// 	{
// 	  tmp[0] = '0';
// 	}
//       else
// 	{
// 	  tmp[0] = buf[i++];
// 	}
//       tmp[1] = buf[i++];
//       itmp = (int) strtol (tmp, NULL, 16);
//       bytes[j++] = itmp;
//     }
//   free (buf);
//   return bytes;
// }

struct rsa_public_key *
der_to_pubkey (asn1object * parent)
{
  struct rsa_public_key *key;
  asn1object *modulus, *publicExponent;

  // Malloc and init key
  if ((key = malloc (sizeof (struct rsa_public_key))) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }
  rsa_public_key_init (key);

  if (!(modulus = assert_integer (first_child (parent))))
    {
      PyErr_Format (ASN1Error, "Expected integer");
      return NULL;
    }
  mpz_import(key->n, modulus->len, 1, 1, 0, 0, modulus->data);

  if (!(publicExponent = assert_integer (next_child (parent, modulus))))
    {
      PyErr_Format (ASN1Error, "Expected integer");
      return NULL;
    }
  mpz_import(key->e, publicExponent->len, 1, 1, 0, 0, publicExponent->data);

  free_asn1object (modulus);
  free_asn1object (publicExponent);
  free_asn1object (parent);
  if (!rsa_public_key_prepare (key))
    {
      PyErr_Format (ASN1Error, "rsa_public_key_prepare failed");
      return NULL;
    }
  return key;
}

int
der_to_keypair (asn1object * parent,
		struct rsa_public_key *pub, struct rsa_private_key *priv)
{
  asn1object *version, *modulus, *publicExponent, *privateExponent,
    *prime1, *prime2, *exponent1, *exponent2, *coefficient;

  rsa_public_key_init (pub);
  rsa_private_key_init (priv);

  if (!(version = assert_integer (first_child (parent))))
    return 0;
  if (version->len != 1 && version->data[0] != 0)
    return 0;
  if (!(modulus = assert_integer (next_child (parent, version))))
    return 0;
  mpz_import(pub->n, modulus->len, 1, 1, 0, 0, modulus->data);
  if (!(publicExponent = assert_integer (next_child (parent, modulus))))
    return 0;
  mpz_import(pub->e, publicExponent->len, 1, 1, 0, 0, publicExponent->data);
  if (!rsa_public_key_prepare (pub))
    {
      PyErr_Format (ASN1Error, "rsa_public_key_prepare failed");
      return 0;
    }

  if (!(privateExponent =
       assert_integer (next_child (parent, publicExponent))))
    {
      PyErr_Format (ASN1Error, "Expected integer");
      return 0;
    }
  mpz_import(priv->d, privateExponent->len, 1, 1, 0, 0, privateExponent->data);
  if (!(prime1 = assert_integer (next_child (parent, privateExponent))))
    return 0;
  mpz_import(priv->p, prime1->len, 1, 1, 0, 0, prime1->data);
  if (!(prime2 = assert_integer (next_child (parent, prime1))))
    {
      PyErr_Format (ASN1Error, "Expected integer");
      return 0;
    }
  mpz_import(priv->q, prime2->len, 1, 1, 0, 0, prime2->data);
  if (!(exponent1 = assert_integer (next_child (parent, prime2))))
    {
      PyErr_Format (ASN1Error, "Expected integer");
      return 0;
    }
  mpz_import(priv->a, exponent1->len, 1, 1, 0, 0, exponent1->data);
  if (!(exponent2 = assert_integer (next_child (parent, exponent1))))
    {
      PyErr_Format (ASN1Error, "Expected integer");
      return 0;
    }
  mpz_import(priv->b, exponent2->len, 1, 1, 0, 0, exponent2->data);
  if (!(coefficient = assert_integer (next_child (parent, exponent2))))
    {
      PyErr_Format (ASN1Error, "Expected integer");
      return 0;
    }
  mpz_import(priv->c, coefficient->len, 1, 1, 0, 0, coefficient->data);
  if (!rsa_private_key_prepare (priv))
    {
      PyErr_Format (ASN1Error, "rsa_private_key_prepare failed");
      return 0;
    }
  free_asn1object (parent);
  free_asn1object (version);
  free_asn1object (modulus);
  free_asn1object (publicExponent);
  free_asn1object (privateExponent);
  free_asn1object (prime1);
  free_asn1object (prime2);
  free_asn1object (exponent1);
  free_asn1object (exponent2);
  free_asn1object (coefficient);

  return 1;
}

uint8_t *
pack_header (asn1object * obj)
{
  uint8_t *header, *h;
  int i, idlen, lenlen, lenptrlen = 0;

  idlen = 1;
  if (obj->tag >= 0x1f)
    {
      idlen++;
    }
  lenlen = 1;
  if (obj->len > 0x7f)
    {
      i = obj->len;
      lenptrlen = 1;
      lenlen++;
      i >>= 7;
      
      while (i > 0xff)
	{
	  lenlen++;
	  i >>= 8;
	}
    }
  if ((header = malloc (idlen + lenptrlen + lenlen)) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }
  h = header;
  *h = (obj->tag_class << 6) | (obj->is_constructed << 5);
  if (obj->tag >= 0x1f)
    {
      *h++ |= 0x1f;
    }
  *h++ |= obj->tag;

  if (lenlen > 1)
    {
      *h++ = 0x80 | lenlen;
      for (i = lenlen - 1; i >= 0; i--)
	{
	  *h++ = (obj->len & (0xff << (8 * i))) >> (8 * i);
	}
    }
  else
    {
      *h = obj->len;
    }
  obj->hlen = idlen + lenptrlen + lenlen;
  return header;
}

int
pack_asn1object (asn1object * obj, uint8_t ** dst, int * len)
{
  uint8_t *header;
  header = pack_header (obj);

  if (((*dst) = realloc (*dst, *len + obj->hlen + obj->len)) == NULL)
    {
      PyErr_Format (ASN1Error, "realloc failed");
      return 0;
    }
  memcpy (&(*dst)[*len], header, obj->hlen);
  free (header);
  *len += obj->hlen;
  memcpy (&(*dst)[*len], obj->data, obj->len);
  *len += obj->len;
  free_asn1object (obj);
  return 1;
}

asn1object *
make_sequence (int argc, ...)
{
  va_list ap;
  asn1object *obj, *child;
  if ((obj = malloc (sizeof (asn1object))) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }
  obj->tag_class = 0;
  obj->is_constructed = 1;
  obj->tag = 16;
  obj->len = 0;
  obj->data = NULL;

  va_start (ap, argc);
  for (int i = 0; i < argc; i++)
    {
      child = va_arg (ap, asn1object *);
      if (!pack_asn1object (child, &obj->data, &obj->len))
	return NULL;
    }
  va_end (ap);
  return obj;
}

asn1object *
encapsulate_in_bitstring (asn1object * child)
{
  asn1object *obj;
  if ((obj = malloc (sizeof (asn1object))) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }
  obj->tag_class = 0;
  obj->is_constructed = 0;
  obj->tag = 3;
  obj->len = 1;
  if ((obj->data = malloc (1)) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }
  obj->data[0] = 0;
  if (!pack_asn1object (child, &obj->data, &obj->len))
    return NULL;
  return obj;
}

asn1object *
make_integer_from_char (char i)
{
  asn1object *obj;
  if ((obj = malloc (sizeof (asn1object))) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }
  obj->tag_class = 0;
  obj->is_constructed = 0;
  obj->tag = 2;
  if ((obj->data = malloc (1)) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }
  obj->data[0] = i;
  obj->len = 1;
  return obj;
}

asn1object *
make_integer_from_gmp (mpz_t integer)
{
  asn1object *obj;
  size_t len;
  
  if ((obj = malloc (sizeof (asn1object))) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }
  obj->tag_class = 0;
  obj->is_constructed = 0;
  obj->tag = 2;

  if ((obj->data = malloc (mpz_sizeinbase (integer, 256))) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }
  mpz_export(obj->data, &len, 1, 1, 0, 0, integer);
  obj->len = (int)len;
  return obj;
}

asn1object *
make_null ()
{
  asn1object *obj;

  if ((obj = malloc (sizeof (asn1object))) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }
  obj->tag_class = 0;
  obj->is_constructed = 0;
  obj->tag = 5;
  obj->len = 0;
  obj->data = NULL;
  return obj;
}

asn1object *
make_oid (char *input)
{
  asn1object *obj;
  char *tofree, *string, *token;
  int nsub = 1, *subs, i = 0, sub;

  if ((obj = malloc (sizeof (asn1object))) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }
  obj->tag_class = 0;
  obj->is_constructed = 0;
  obj->tag = 6;
  obj->len = 1;

  tofree = string = strdup (input);
  for (token = string; *token; token++)
    {
      if (*token == '.')
	{
	  nsub++;
	}
    }

  if ((subs = malloc (sizeof (int) * nsub)) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }
  while ((token = strsep (&string, ".")))
    {
      sub = (int) strtol (token, NULL, 10);
      subs[i++] = sub;
      if (i > 1)
	{
	  while (sub > 0x7f)
	    {
	      obj->len++;
	      sub >>= 7;
	    }
	  obj->len++;
	}
    }
  free (tofree);

  if ((obj->data = malloc (obj->len)) == NULL)
    {
      PyErr_Format(PyExc_MemoryError, "malloc failed");
      return NULL;
    }

  obj->data[0] = (uint8_t) (subs[0] * 40 + subs[1]);
  obj->len = 1;
  for (i = 2; i < nsub; i++)
    {
      for (int j = 4; j >= 0; j--)
	{
	  if ((subs[i] >> (j * 7)) & 0x7f)
	    {
	      obj->data[obj->len++] = (uint8_t) (((subs[i] >> (j * 7)) & 0x7f)
						 | (j ? 0x80 : 0));
	    }
	}
    }
  free (subs);
  return obj;
}

asn1object *
pubkey_to_der (struct rsa_public_key * key)
{
  asn1object *obj;

  obj = make_sequence (2,
		       make_sequence (2,
				      make_oid ("1.2.840.113549.1.1.1"),
				      make_null ()),
		       encapsulate_in_bitstring (make_sequence (2,
								make_integer_from_gmp
								(key->n),
								make_integer_from_gmp
								(key->e))));
  return obj;
}

asn1object *
keypair_to_der (struct rsa_public_key * pub, struct rsa_private_key * priv)
{
  asn1object *obj;
  obj = make_sequence (9,
		       make_integer_from_char (0),
		       make_integer_from_gmp (pub->n),
		       make_integer_from_gmp (pub->e),
		       make_integer_from_gmp (priv->d),
		       make_integer_from_gmp (priv->p),
		       make_integer_from_gmp (priv->q),
		       make_integer_from_gmp (priv->a),
		       make_integer_from_gmp (priv->b),
		       make_integer_from_gmp (priv->c));

  return obj;
}

int
write_object_to_file (asn1object * obj, char *filename)
{
  uint8_t *buf = NULL;
  int len = 0;
  FILE *f;

  if (!pack_asn1object (obj, &buf, &len))
    return 0;

  if ((f = fopen (filename, "w")) == NULL)
    {
      PyErr_Format (ASN1Error, "Failed to open file '%s' for writing",
		    filename); 
      return 0;
    }
  if (fwrite (buf, len, 1, f) < 1)
    {
      PyErr_Format (ASN1Error, "Failed to write to file '%s'", filename); 
      return 0;
    }
  free (buf);
  fclose(f);
  return 1;
}

struct rsa_public_key *
get_public_key_from_certfile (uint8_t * der)
{
  asn1object *certificate, *tbsCertificate, *version, *serialNumber,
    *signature, *issuer, *validity, *subject, *subjectPublicKeyInfo,
    *algorithm, *subjectPublicKey, *rsaPublicKey;
  struct rsa_public_key *pub;

  // Navigate ASN.1 Tree
  if (!(certificate = assert_sequence (root_object (der))))
    return NULL;
  if (!(tbsCertificate = assert_sequence (first_child (certificate))))
    return NULL;
  if (!(version = assert_context0 (first_child (tbsCertificate))))
    return NULL;
  if (!(serialNumber = assert_integer (next_child (tbsCertificate, version))))
    return NULL;
  if (!
      (signature =
       assert_sequence (next_child (tbsCertificate, serialNumber))))
    return NULL;
  if (!(issuer = assert_sequence (next_child (tbsCertificate, signature))))
    return NULL;
  if (!(validity = assert_sequence (next_child (tbsCertificate, issuer))))
    return NULL;
  if (!(subject = assert_sequence (next_child (tbsCertificate, validity))))
    return NULL;
  if (!(subjectPublicKeyInfo = assert_sequence (next_child (tbsCertificate,
							    subject))))
    return NULL;
  if (!(algorithm = assert_sequence (first_child (subjectPublicKeyInfo))))
    return NULL;
  if (!(subjectPublicKey = assert_bitstring (next_child (subjectPublicKeyInfo,
							 algorithm))))
    return NULL;
  if (!(rsaPublicKey = assert_sequence (first_child (subjectPublicKey))))
    return NULL;
  free_asn1object (certificate);
  free_asn1object (tbsCertificate);
  free_asn1object (version);
  free_asn1object (serialNumber);
  free_asn1object (signature);
  free_asn1object (issuer);
  free_asn1object (validity);
  free_asn1object (subject);
  free_asn1object (subjectPublicKeyInfo);
  free_asn1object (algorithm);

  pub = der_to_pubkey (rsaPublicKey);
  free_asn1object (subjectPublicKey);
  free (der);
  return pub;
}

struct rsa_public_key *
get_public_key_from_file (uint8_t * der)
{
  asn1object *publicKeyInfo, *algorithm, *publicKey, *rsaPublicKey;

  // Navigate ASN.1 Tree
  if (!(publicKeyInfo = assert_sequence (root_object (der))))
    return NULL;
  if (!(algorithm = assert_sequence (first_child (publicKeyInfo))))
    return NULL;
  if (!(publicKey = assert_bitstring (next_child (publicKeyInfo, algorithm))))
    return NULL;
  if (!(rsaPublicKey = assert_sequence (first_child (publicKey))))
    return NULL;

  free (der);
  free_asn1object (publicKeyInfo);
  free_asn1object (algorithm);
  free_asn1object (publicKey);

  return der_to_pubkey (rsaPublicKey);
}

int
get_keypair_from_file (uint8_t * der,
		       struct rsa_public_key *pub,
		       struct rsa_private_key *priv)
{
  asn1object *rsaPrivateKey;
  // Navigate ASN.1 Tree
  if (!(rsaPrivateKey = assert_sequence (root_object (der))))
    return 0;
  free (der);
  return der_to_keypair (rsaPrivateKey, pub, priv);
}
