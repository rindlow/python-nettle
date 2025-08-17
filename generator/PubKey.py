# coding: utf-8
#
# PubKey.py
#
# Copyright (C) 2017, 2018 Henrik Rindlöw
#
# This file is part of python-nettle.
#
# Python-nettle is free software: you can redistribute it and/or
# modify it under the terms of either:
#
#   * the GNU Lesser General Public License as published by the Free
#     Software Foundation; either version 3 of the License, or (at your
#     option) any later version.
#
# or
#
#   * the GNU General Public License as published by the Free
#     Software Foundation; either version 2 of the License, or (at your
#     option) any later version.
#
# or both in parallel, as here.
#
# Python-nettle is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received copies of the GNU General Public License and
# the GNU Lesser General Public License along with this program.  If
# not, see http://www.gnu.org/licenses/.

from CClass import CClass

yarrowinit = '''
    PyObject *obj = NULL;
    pynettle_Yarrow *yarrow;

    if (! PyArg_ParseTuple (args, "|O", &obj))
      {
        return -1;
      }
    if (obj != NULL)
      {
        if (PyObject_TypeCheck (obj, &pynettle_Yarrow_Type))
          {
            yarrow = (pynettle_Yarrow *)obj;
            self->yarrow = yarrow;
            Py_INCREF (self->yarrow);
          }
        else
          {
            PyErr_Format (PyExc_TypeError, "Expected Yarrow object");
            return -1;
          }
      }
    else
      {
        self->yarrow = (pynettle_Yarrow *) PyObject_CallObject (
            (PyObject *)& pynettle_Yarrow_Type, NULL);
      }'''

encryptbody = '''
    mpz_t ciphertext;
    uint8_t *data;
    size_t len;
    Py_buffer buffer;

    if (! PyArg_ParseTuple (args, "y*", &buffer))
      {
        return NULL;
      }
    mpz_init (ciphertext);
    if (! rsa_encrypt (self->pub, self->yarrow->ctx,
                       (nettle_random_func *) &yarrow256_random,
                       buffer.len, buffer.buf, ciphertext))
      {
        PyErr_Format (RSAError, "Failed to encrypt data");
        return NULL;
      }
    if ((data = malloc (mpz_sizeinbase (ciphertext, 256))) == NULL)
      {
        PyErr_Format (PyExc_MemoryError, "malloc failed");
        return NULL;
      }
    mpz_export (data, &len, 1, 1, 0, 0, ciphertext);
    return PyBytes_FromStringAndSize ((const char *) data, len);'''

def oaep_encryptbody(hashfunc):
    return f'''
    size_t datalen = self->pub->size;
    uint8_t *data;
    Py_buffer buffer;
    Py_buffer label;
    static char *kwlist[] = {{"msg", "label", NULL}};
    buffer.buf = NULL; buffer.len = 0;
    label.buf = NULL; label.len = 0;
    if (! PyArg_ParseTupleAndKeywords (args, kwds, "y*|y*", kwlist,
        &buffer, &label))
      {{
        return NULL;
      }}
    PyObject *ciphertext = PyBytes_FromStringAndSize (NULL, datalen);
    data = (unsigned char *)PyBytes_AsString(ciphertext);
    if (! rsa_oaep_{hashfunc}_encrypt (self->pub, self->yarrow->ctx,
                       (nettle_random_func *) &yarrow256_random,
                       label.len, label.buf,
                       buffer.len, buffer.buf, data))
      {{
        PyErr_Format (RSAError, "Failed to encrypt data");
        return NULL;
      }}
    return ciphertext;'''


def signbody():
    body = '''
        mpz_t signature;
        PyObject *obj;
        size_t len = 256;
        uint8_t data[len];
        mpz_init (signature);
        if (! PyArg_ParseTuple (args, "O", &obj))
          {
            return NULL;
          }'''
    for hashfunc in ('md5', 'sha1', 'sha256', 'sha512'):
        body += f'''
        if (PyObject_TypeCheck (obj, &pynettle_{hashfunc}_Type))
          {{
            pynettle_{hashfunc} *hash = (pynettle_{hashfunc} *)obj;
            rsa_{hashfunc}_sign (self->key, hash->ctx, signature);
          }}'''
    body += '''
        mpz_export (data, &len, 1, 1, 0, 0, signature);
        return PyBytes_FromStringAndSize ((const char *) data, len);'''
    return body

def verifybody():
    body = '''
        mpz_t signature;
        PyObject *obj;
        Py_buffer buffer;

        if (! PyArg_ParseTuple (args, "y*O", &buffer, &obj))
          {
            return NULL;
          }
        mpz_init (signature);
        mpz_import (signature, buffer.len, 1, 1, 0, 0, buffer.buf);'''
    for hashfunc in ('md5', 'sha1', 'sha256', 'sha512'):
        body += f'''
        if (PyObject_TypeCheck (obj, &pynettle_{hashfunc}_Type))
          {{
            pynettle_{hashfunc} *hash = (pynettle_{hashfunc} *)obj;
            return PyBool_FromLong (rsa_{hashfunc}_verify (self->pub, hash->ctx,
                                                      signature));
          }}'''
    body += '''
        PyErr_Format (PyExc_TypeError, "Wrong type of hash");
        return NULL;'''
    return body

def bufferbody(members: dict[str, str]):
    kwlist = f'{{{', '.join(f'"{m}"' for m in members)}, NULL}}'
    buffers = [f'buffer_{m}' for m in members]
    body = f'''
    Py_buffer {', '.join(buffers)};
    static char *kwlist[] = {kwlist};

    if (! PyArg_ParseTupleAndKeywords (args, kwds, "{'y*' * len(members)}",
        kwlist, {', '.join(f'&{buf}' for buf in buffers)}))
      {{
        return NULL;
      }}'''
    for member, key in members.items():
        body += (f'\n    mpz_import (self->{key}->{member},'
                 f' buffer_{member}.len, 1, 1, 0, 0, buffer_{member}.buf);')
    body += '''
    if (!rsa_public_key_prepare (self->pub))
      {
        PyErr_Format (RSAError, "rsa_public_key_prepare failed");
        return 0;
      }'''
    if 'key' in members.values():
      body += '''
    if (!rsa_private_key_prepare (self->key))
      {
        PyErr_Format (RSAError, "rsa_private_key_prepare failed");
        return 0;
      }'''
    body += '''
    Py_RETURN_NONE;\n'''
    return body


class Yarrow(CClass):

    def __init__(self):
        CClass.__init__(self, 'Yarrow',
                        'Yarrow Pseudo Random Number Generator')

        self.add_member(
            name='yarrow',
            decl='struct yarrow256_ctx *ctx;',
            init='self->ctx = NULL;',
            dealloc='PyMem_Free (self->ctx);\nself->ctx = NULL;')
        self.add_method(
            'random',
            docs='Generate random bytes',
            args='METH_VARARGS',
            docargs='len',
            body='''
                int len;
                uint8_t *data;
                PyObject *bytes;
                if (! PyArg_ParseTuple (args, "i", &len))
                  {
                    return NULL;
                  }
                if ((data = malloc(len)) == NULL)
                  {
                    return PyErr_NoMemory ();
                  }
                yarrow256_random (self->ctx, len, data);
                bytes = PyBytes_FromStringAndSize ((const char *) data, len);
                free(data);
                return bytes;
            ''')
        self.add_to_init_body('''
            ssize_t res;
            int fd;
            uint8_t seed[YARROW256_SEED_FILE_SIZE];

            if ((self->ctx = PyMem_Malloc (sizeof (struct yarrow256_ctx))) \\
                == NULL)
              {
                PyErr_NoMemory ();
                return -1;
              }
            yarrow256_init (self->ctx, 0, NULL);
            if ((fd = open ("/dev/random", O_RDONLY)) < 0)
              {
                PyErr_Format (RandomError, "Failed to open /dev/random:");
                return -1;
              }
            do
              {
                res = read (fd, seed, YARROW256_SEED_FILE_SIZE);
              }
            while (res < 0 && errno == EAGAIN);
            if (res < 0 && errno != EAGAIN)
              {
                PyErr_Format (RandomError, "Failed to read /dev/random:");
                return -1;
              }
            yarrow256_seed (self->ctx, YARROW256_SEED_FILE_SIZE, seed);
          ''')


class RSAKeyPair(CClass):

    def __init__(self):
        CClass.__init__(self, 'RSAKeyPair', 'RSA Key Pair', args='[yarrow]')
        self.to_be_subclassed = True

        self.add_member(
            name='pub',
            decl='struct rsa_public_key *pub',
            alloc='''
               if ((self->pub = PyMem_Malloc (sizeof (struct \\
                    rsa_public_key))) == NULL)
                 {
                   return PyErr_NoMemory ();
                 }
               ''',
            init='rsa_public_key_init (self->pub);',
            dealloc='''
                rsa_public_key_clear (self->pub);
                PyMem_Free (self->pub);
                self->pub = NULL;''')
        self.add_member(
            name='key',
            decl='struct rsa_private_key *key',
            alloc='''
               if ((self->key = PyMem_Malloc (sizeof (struct \\
                   rsa_private_key))) == NULL)
                 {
                   return PyErr_NoMemory ();
                 }''',
            init='rsa_private_key_init (self->key);',
            dealloc='''
                rsa_private_key_clear (self->key);
                PyMem_Free (self->key);
                self->key = NULL;''')
        self.add_member(
            name='yarrow',
            decl='pynettle_Yarrow *yarrow',
            init='self->yarrow = NULL;',
            dealloc='Py_DECREF (self->yarrow);',
            docs='Yarrow instance',
            flags='READONLY',
            type='T_OBJECT',
            public=True)
        self.add_to_init_body(yarrowinit)

        self.add_method(
            'genkey',
            docs='Generate a new RSA keypair',
            args='METH_VARARGS',
            docargs='n_size, e_size',
            body='''
                int res, n_size, e_size;
                if (! PyArg_ParseTuple (args, "ii", &n_size, &e_size))
                  {
                    return NULL;
                  }
                res = rsa_generate_keypair (self->pub, self->key,
                                            self->yarrow->ctx,
                                            (nettle_random_func *) \\
                                             &yarrow256_random,
                                            NULL, NULL,
                                            n_size, e_size);
                if (res == 0)
                  {
                    PyErr_Format (RSAError, "genkey_failed");
                    return NULL;
                  }
                Py_RETURN_NONE;
            ''')

        self.add_method(
            'from_pkcs1',
            docs='Read key (keypair) from buffer in PKCS#1 format',
            args='METH_VARARGS',
            docargs='bytes',
            body='''
                Py_buffer buffer;
                if (! PyArg_ParseTuple (args, "y*", &buffer))
                  {
                    return NULL;
                  }
                if (! keypair_from_pkcs1 ((uint8_t *) buffer.buf, self->pub, \\
                                         self->key))
                  {
                    PyErr_Format (ASN1Error, "Failed to find key in buffer");
                    return NULL;
                  }
                Py_RETURN_NONE;
              ''')
        self.add_method(
            'from_pkcs8',
            docs='Read key (keypair) from buffer in plain PKCS#8 format',
            args='METH_VARARGS',
            docargs='bytes',
            body='''
                Py_buffer buffer;
                if (! PyArg_ParseTuple (args, "y*", &buffer))
                  {
                    return NULL;
                  }
                if (! keypair_from_pkcs8 ((uint8_t *) buffer.buf, self->pub, \\
                                          self->key))
                  {
                    PyErr_Format (ASN1Error, "Failed to find key in buffer");
                    return NULL;
                  }
                Py_RETURN_NONE;
              ''')
        self.add_method(
            'from_params',
            docs='Read key (keypair) from params',
            args='METH_VARARGS | METH_KEYWORDS',
            docargs='bytes, bytes, bytes, bytes, bytes, bytes, bytes, bytes',
            body=bufferbody({'n': 'pub', 'e': 'pub', 'd': 'key', 'p': 'key',
                             'q': 'key', 'a': 'key', 'b': 'key', 'c': 'key'}))
        self.add_method(
            'to_pkcs1_key',
            docs='Write key (keypair) to buffer in PKCS#1 format',
            args='METH_NOARGS',
            body='''
                uint8_t *data = NULL;
                int len = 0;
                if (! keypair_to_pkcs1 (self->pub, self->key, &data, &len))
                  {
                    PyErr_Format (ASN1Error, "Failed to encode key");
                  }
                return PyBytes_FromStringAndSize ((const char *) data, len);
            ''')

        self.add_method(
            name='encrypt',
            args='METH_VARARGS',
            docs='Encrypt data',
            docargs='bytes',
            body=encryptbody)

        for hashfunc in ('sha256', 'sha384', 'sha512'):
            self.add_method(
                name=f'oaep_{hashfunc}_encrypt',
                args='METH_VARARGS | METH_KEYWORDS',
                docs=f'Encrypt data using RSA with the OAEP padding scheme and {hashfunc} hash',
                docargs='bytes, label',
                body=oaep_encryptbody(hashfunc))

        self.add_method(
            name='decrypt',
            args='METH_VARARGS',
            docs='Decrypt data',
            docargs='bytes',
            body='''
                mpz_t ciphertext;
                size_t datalen = 256;
                uint8_t data[datalen];
                Py_buffer buffer;
                if (! PyArg_ParseTuple (args, "y*", &buffer))
                  {
                    return NULL;
                  }
                mpz_init (ciphertext);
                mpz_import (ciphertext, buffer.len, 1, 1, 0, 0, buffer.buf);
                if (! rsa_decrypt (self->key, &datalen, data, ciphertext))
                  {
                    PyErr_Format (RSAError, "Failed to decrypt data");
                    return NULL;
                  }
                return PyBytes_FromStringAndSize ((const char *) data, \\
                        datalen);
            ''')

        for hashfunc in ('sha256', 'sha384', 'sha512'):
          self.add_method(
              name=f'oaep_{hashfunc}_decrypt',
              args='METH_VARARGS | METH_KEYWORDS',
              docs='Decrypt data',
              docargs='bytes',
              body=f'''
                  size_t datalen = self->pub->size;
                  uint8_t *data;
                  Py_buffer buffer;
                  Py_buffer label;
                  static char *kwlist[] = {{"msg", "label", NULL}};
                  buffer.buf = NULL; buffer.len = 0;
                  label.buf = NULL; label.len = 0;
                  if (! PyArg_ParseTupleAndKeywords (args, kwds, "y*|y*", kwlist,
                      &buffer, &label))
                    {{
                      return NULL;
                    }}
                  if ((data = PyMem_Malloc (datalen)) == NULL)
                    {{
                      return PyErr_NoMemory ();
                    }}
                  if (! rsa_oaep_{hashfunc}_decrypt (self->pub, self->key, self->yarrow->ctx,
                        (nettle_random_func *) &yarrow256_random,
                        label.len, label.buf,
                        &datalen, data, buffer.buf))
                    {{
                      PyErr_Format (RSAError, "Failed to decrypt data");
                      return NULL;
                    }}
                  return PyBytes_FromStringAndSize ((const char *) data, \\
                          datalen);''')


        self.add_method(
            name='sign',
            args='METH_VARARGS',
            docs='Sign a hash',
            docargs='hash',
            body=signbody())

        self.add_method(
            name='verify',
            args='METH_VARARGS',
            docs='Verify a signature',
            docargs='signature, hash',
            body=verifybody())

        self.add_richcompare(
            body='''
                pynettle_RSAKeyPair *self, *other;
                if (! (PyObject_TypeCheck (a, &pynettle_RSAKeyPair_Type)
                       && PyObject_TypeCheck (b, &pynettle_RSAKeyPair_Type)))
                  {
                    Py_RETURN_FALSE;
                  }
                self = (pynettle_RSAKeyPair *)a;
                other = (pynettle_RSAKeyPair *)b;
                if (mpz_cmp (self->pub->n, other->pub->n) == 0
                    && mpz_cmp (self->pub->e, other->pub->e) == 0
                    && mpz_cmp (self->key->d, other->key->d) == 0
                    && mpz_cmp (self->key->p, other->key->p) == 0
                    && mpz_cmp (self->key->q, other->key->q) == 0
                    && mpz_cmp (self->key->a, other->key->a) == 0
                    && mpz_cmp (self->key->b, other->key->b) == 0
                    && mpz_cmp (self->key->c, other->key->c) == 0)
                  {
                    switch (op)
                      {
                      case Py_EQ:
                        Py_RETURN_TRUE;
                      case Py_NE:
                        Py_RETURN_FALSE;
                      default:
                        PyErr_Format (PyExc_TypeError, "Can't compare keys");
                        return NULL;
                      }
                  }
                switch (op)
                  {
                  case Py_EQ:
                    Py_RETURN_FALSE;
                  case Py_NE:
                    Py_RETURN_TRUE;
                  default:
                    PyErr_Format (PyExc_TypeError, "Can't compare keys");
                    return NULL;
                  }
              ''')

        self.add_getsetter(
            'public_key',
            gbody='''
                PyObject * module = PyImport_ImportModule("nettle");
                PyObject * pk = PyObject_GetAttrString(module, "RSAPubKey");
                PyObject * args = PyTuple_Pack(1, (PyObject *)self->yarrow);
                pynettle_RSAPubKey *pubkey = (pynettle_RSAPubKey *) \\
                   PyObject_CallObject (pk, args);
                mpz_set (pubkey->pub->n, self->pub->n);
                mpz_set (pubkey->pub->e, self->pub->e);
                if (! rsa_public_key_prepare (pubkey->pub))
                  {
                    PyErr_Format (RSAError, "Failed to prepare key");
                    return NULL;
                  }
                return (PyObject *)pubkey;
            ''',
            docs='The public part of the keypair')

        self.add_getsetter(
            'size',
            gbody='''
                return (PyObject *)PyLong_FromUnsignedLong(self->pub->size);
            ''',
            docs='The size, in octets, of the modulo')

    def write_python_subclass(self, f):
        # Do not write copying code, this class will be subclassed
        pass


class RSAPubKey(CClass):

    def __init__(self):
        CClass.__init__(self, 'RSAPubKey', 'Public part of RSA Key Pair',
                        args='[yarrow]')

        self.add_member(
            name='pub',
            decl='struct rsa_public_key *pub',
            alloc='if ((self->pub = PyMem_Malloc (sizeof (struct'
            ' rsa_public_key))) == NULL)\n    {\n'
            '      return PyErr_NoMemory ();\n    }\n',
            init='rsa_public_key_init (self->pub);',
            dealloc='PyMem_Free (self->pub);\nself->pub = NULL;')
        self.add_member(
            name='yarrow',
            decl='pynettle_Yarrow *yarrow',
            init='self->yarrow = NULL;',
            dealloc='Py_DECREF (self->yarrow);',
            docs='Yarrow instance',
            flags='READONLY',
            type='T_OBJECT',
            public=True)

        self.add_method(
            'to_pkcs8_key',
            docs='Write key to buffer in PKCS#8 format',
            args='METH_NOARGS',
            body='''
                uint8_t *data = NULL;
                int len = 0;
                if (! pubkey_to_pkcs8 (self->pub, &data, &len))
                  {
                    PyErr_Format (RSAError, "Failed to encode key");
                  }
                return PyBytes_FromStringAndSize ((const char *) data, len);
            ''')

        self.add_method(
            'from_pkcs1',
            docs='Read key from buffer in PKCS#1 format',
            docargs='bytes',
            args='METH_VARARGS',
            body='''
                Py_buffer buffer;
                if (! PyArg_ParseTuple (args, "y*", &buffer))
                  {
                    return NULL;
                  }
                if ((self->pub = pubkey_from_pkcs1 ((uint8_t *) buffer.buf)) \\
                     == NULL)
                  {
                    PyErr_Format (ASN1Error, "Failed to find key in buffer");
                    return NULL;
                  }
                Py_RETURN_NONE;
              ''')

        self.add_method(
            'from_pkcs8',
            docs='Read key from buffer in PKCS#8 format',
            docargs='bytes',
            args='METH_VARARGS',
            body='''
                Py_buffer buffer;
                if (! PyArg_ParseTuple (args, "y*", &buffer))
                  {
                    return NULL;
                  }
                if ((self->pub = pubkey_from_pkcs8 ((uint8_t *) buffer.buf)) \\
                     == NULL)
                  {
                    PyErr_Format (ASN1Error, "Failed to find key in buffer");
                    return NULL;
                  }
                Py_RETURN_NONE;
              ''')
        self.add_method(
            'from_params',
            docs='Read key (pubkey) from params',
            args='METH_VARARGS | METH_KEYWORDS',
            docargs='bytes, bytes',
            body=bufferbody({'n': 'pub', 'e': 'pub'}))
        self.add_method(
            'from_cert',
            docs='Read key from buffer containing X.509 certificate',
            docargs='bytes',
            args='METH_VARARGS',
            body='''
                Py_buffer buffer;
                if (! PyArg_ParseTuple (args, "y*", &buffer))
                  {
                    return NULL;
                  }
                if ((self->pub = pubkey_from_cert ((uint8_t *) buffer.buf)) \\
                     == NULL)
                  {
                    PyErr_Format (ASN1Error, "Failed to read file");
                    return NULL;
                  }
                fprintf(stderr, "pubkey_from_cert returned %p\\n", self->pub);
                Py_RETURN_NONE;
            ''')

        self.add_richcompare(body='''
  pynettle_RSAPubKey *self, *other;
  if (! (PyObject_TypeCheck (a, &pynettle_RSAPubKey_Type)
         && PyObject_TypeCheck (b, &pynettle_RSAPubKey_Type)))
    {
      Py_RETURN_FALSE;
    }
  self = (pynettle_RSAPubKey *)a;
  other = (pynettle_RSAPubKey *)b;

  if (mpz_cmp (self->pub->n, other->pub->n) == 0
      && mpz_cmp (self->pub->e, other->pub->e) == 0)
    {
      switch (op)
        {
        case Py_EQ:
          Py_RETURN_TRUE;
        case Py_NE:
          Py_RETURN_FALSE;
        default:
          PyErr_Format (PyExc_TypeError, "Can't compare keys");
          return NULL;
        }
    }
  switch (op)
    {
    case Py_EQ:
      Py_RETURN_FALSE;
    case Py_NE:
      Py_RETURN_TRUE;
    default:
      PyErr_Format (PyExc_TypeError, "Can't compare keys");
      return NULL;
    }
''')

        self.add_method(
            name='encrypt',
            args='METH_VARARGS',
            docs='Encrypt data',
            body=encryptbody)

        for hashfunc in ('sha256', 'sha384', 'sha512'):
            self.add_method(
                name=f'oaep_{hashfunc}_encrypt',
                args='METH_VARARGS | METH_KEYWORDS',
                docs=f'Encrypt data using RSA with the OAEP padding scheme and {hashfunc} hash',
                docargs='label, bytes',
                body=oaep_encryptbody(hashfunc))

        self.add_method(
            name='verify',
            args='METH_VARARGS',
            docs='Verify a signature',
            body=verifybody())

        self.add_to_init_body(yarrowinit)

        self.add_getsetter(
            'size',
            gbody='''
                return (PyObject *)PyLong_FromUnsignedLong(self->pub->size);
            ''',
            docs='The size, in octets, of the modulo')

    def write_python_subclass(self, f):
        # Do not write copying code, this class will be subclassed
        pass
