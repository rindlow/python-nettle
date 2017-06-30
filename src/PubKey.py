from CClass import CClass

encryptbody = '''
  mpz_t ciphertext;
  uint8_t *data;
  size_t len;
#if PY_MAJOR_VERSION >= 3
  Py_buffer buffer;

  if (! PyArg_ParseTuple(args, "y*", &buffer)) {
#else
  nettle_py2buf buffer;
  if (! PyArg_ParseTuple(args, "t#",
                         &buffer.buf, &buffer.len)) {
#endif
    return NULL;
  }
  mpz_init(ciphertext);
  if (! rsa_encrypt(self->pub, self->yarrow->ctx,
                    (nettle_random_func *) &yarrow256_random,
                    buffer.len, buffer.buf, ciphertext))
  {
     PyErr_Format (RSAError, "Failed to encrypt data");
     return NULL;
  }
  if ((data = malloc (mpz_sizeinbase (ciphertext, 256))) == NULL)
  {
    PyErr_Format(PyExc_MemoryError, "malloc failed");
    return NULL;
  }
  mpz_export(data, &len, 1, 1, 0, 0, ciphertext);
  return PyBytes_FromStringAndSize((const char *)data, len);
'''

verifybody = '''
  mpz_t signature;
  PyObject *obj;
  pynettle_sha256 *hash;
#if PY_MAJOR_VERSION >= 3
  Py_buffer buffer;

  if (! PyArg_ParseTuple(args, "y*O", &buffer, &obj)) {
#else
  nettle_py2buf buffer;
  if (! PyArg_ParseTuple(args, "t#O",
                         &buffer.buf, &buffer.len, &obj)) {
#endif
    return NULL;
  }

  mpz_init(signature);
  mpz_import(signature, buffer.len, 1, 1, 0, 0, buffer.buf);

  if (PyObject_TypeCheck (obj, &pynettle_sha256_Type))
  {
    hash = (pynettle_sha256 *)obj;
    return PyBool_FromLong(rsa_sha256_verify(self->pub, hash->ctx, signature));
  }
  PyErr_Format (PyExc_TypeError, "Wrong type of hash");
  return NULL;
'''


class Yarrow(CClass):

    def __init__(self):
        CClass.__init__(self, 'Yarrow',
                        'Yarrow Pseudo Random Number Generator')

        self.add_member(
            name='yarrow',
            decl='struct yarrow256_ctx *ctx;',
            alloc='',
            init='  self->ctx = NULL;',
            dealloc='PyMem_Free (self->ctx);\n  self->ctx = NULL;')
        self.add_to_init_body('''
    ssize_t res;
    int fd;
    uint8_t seed[YARROW256_SEED_FILE_SIZE];

    if ((self->ctx = PyMem_Malloc (sizeof (struct yarrow256_ctx))) == NULL)
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
        CClass.__init__(self, 'RSAKeyPair', 'RSA Key Pair')

        self.add_member(
            name='pub',
            decl='struct rsa_public_key *pub',
            alloc='if ((self->pub = PyMem_Malloc (sizeof (struct'
            ' rsa_public_key))) == NULL)\n    {\n'
            '      return PyErr_NoMemory ();\n    }\n',
            init='  rsa_public_key_init (self->pub);',
            dealloc='PyMem_Free (self->pub);\n  self->pub = NULL;')
        self.add_member(
            name='key',
            decl='struct rsa_private_key *key',
            alloc='if ((self->key = PyMem_Malloc (sizeof'
            ' (struct rsa_private_key))) == NULL)\n    {\n'
            '      return PyErr_NoMemory ();\n    }\n',
            init='  rsa_private_key_init (self->key);',
            dealloc='PyMem_Free (self->key);\n  self->key = NULL;')
        self.add_member(
            name='yarrow',
            decl='pynettle_Yarrow *yarrow',
            init='  self->yarrow = NULL;',
            dealloc='Py_DECREF (self->yarrow);')
        self.add_to_init_body('''
  PyObject *obj = NULL;
  pynettle_Yarrow *yarrow;

  if (! PyArg_ParseTuple(args, "|O", &obj))
  {
    return -1;
  }
  if (obj != NULL)
  {
    if (PyObject_TypeCheck (obj, &pynettle_Yarrow_Type))
    {
      yarrow = (pynettle_Yarrow *)obj;
      self->yarrow = yarrow;
      Py_INCREF(self->yarrow);
    }
    else
    {
      PyErr_Format (PyExc_TypeError, "Expected Yarrow object");
      return -1;
    }
  }
  else
  {
    self->yarrow = (pynettle_Yarrow *) PyObject_CallObject(
         (PyObject *)& pynettle_Yarrow_Type, NULL);
  }
''')

        self.add_method('genkey',
                        docs='Generate a new RSA keypair',
                        args='METH_VARARGS',
                        body='''
    int res, n_size, e_size;
    if (! PyArg_ParseTuple(args, "ii", &n_size, &e_size)) {
        return NULL;
    }

    res = rsa_generate_keypair (self->pub, self->key,
                                self->yarrow->ctx,
                                (nettle_random_func *) &yarrow256_random,
                                NULL, NULL,
                                n_size, e_size);
    if (res == 0)
    {
        PyErr_Format (RSAError, "genkey_failed");
        return NULL;
    }
    Py_RETURN_NONE;
''')

        self.add_method('save_key',
                        docs='Save key (keypair) to file (der)',
                        args='METH_VARARGS',
                        body='''
    char *path;
    if (! PyArg_ParseTuple (args, "s", &path))
    {
        return NULL;
    }
    if (! write_object_to_file (keypair_to_der (self->pub, self->key), path))
    {
        PyErr_Format (RSAError, "Failed to write file");
        return NULL;
    }
    Py_RETURN_NONE;
''')

        self.add_method('read_key',
                        docs='Read key (keypair) from file (der or pem)',
                        args='METH_VARARGS',
                        body='''
    char *path;
    if (! PyArg_ParseTuple (args, "s", &path))
    {
        return NULL;
    }
    if (! get_keypair_from_file (read_file (path), self->pub, self->key))
    {
        PyErr_Format (RSAError, "Failed to read file");
        return NULL;
    }
    Py_RETURN_NONE;
''')

        self.add_method(
            name='encrypt',
            args='METH_VARARGS',
            docs='Encrypt data',
            body=encryptbody)

        self.add_method(
            name='decrypt',
            args='METH_VARARGS',
            docs='Decrypt data',
            body='''
  mpz_t ciphertext;
  size_t datalen = 256;
  uint8_t data[datalen];
#if PY_MAJOR_VERSION >= 3
  Py_buffer buffer;

  if (! PyArg_ParseTuple(args, "y*", &buffer)) {
#else
  nettle_py2buf buffer;
  if (! PyArg_ParseTuple(args, "t#",
                         &buffer.buf, &buffer.len)) {
#endif
    return NULL;
  }
  mpz_init(ciphertext);
  mpz_import(ciphertext, buffer.len, 1, 1, 0, 0, buffer.buf);

  if (! rsa_decrypt(self->key, &datalen, data, ciphertext))
  {
     PyErr_Format (RSAError, "Failed to decrypt data");
     return NULL;
  }
  return PyBytes_FromStringAndSize((const char *)data, datalen);
''')

        self.add_method(
            name='sign',
            args='METH_VARARGS',
            docs='Sign a hash',
            body='''
  mpz_t signature;
  PyObject *obj;
  pynettle_sha256 *hash;
  size_t len = 256;
  uint8_t data[len];
  mpz_init(signature);

  if (! PyArg_ParseTuple(args, "O", &obj))
  {
    return NULL;
  }
  if (PyObject_TypeCheck (obj, &pynettle_sha256_Type))
  {
    hash = (pynettle_sha256 *)obj;
    rsa_sha256_sign(self->key, hash->ctx, signature);
  }
  mpz_export(data, &len, 1, 1, 0, 0, signature);
  return PyBytes_FromStringAndSize((const char *)data, len);
''')

        self.add_method(
            name='verify',
            args='METH_VARARGS',
            docs='Verify a signature',
            body=verifybody)

        self.add_richcompare(body='''
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

        self.add_getsetter('public_key', gbody='''
    pynettle_RSAPubKey *pubkey = (pynettle_RSAPubKey *) PyObject_CallObject(
         (PyObject *)& pynettle_RSAPubKey_Type, NULL);
    mpz_set(pubkey->pub->n, self->pub->n);
    mpz_set(pubkey->pub->e, self->pub->e);
    if (! rsa_public_key_prepare (pubkey->pub))
    {
        PyErr_Format (RSAError, "Failed to prepare key");
        return NULL;
    }
    return (PyObject *)pubkey;
    ''')


class RSAPubKey(CClass):

    def __init__(self):
        CClass.__init__(self, 'RSAPubKey', 'Public part of RSA Key Pair')

        self.add_member(
            name='pub',
            decl='struct rsa_public_key *pub',
            alloc='if ((self->pub = PyMem_Malloc (sizeof (struct'
            ' rsa_public_key))) == NULL)\n    {\n'
            '      return PyErr_NoMemory ();\n    }\n',
            init='  rsa_public_key_init (self->pub);',
            dealloc='PyMem_Free (self->pub);\n  self->pub = NULL;')
        self.add_member(
            name='yarrow',
            decl='pynettle_Yarrow *yarrow',
            alloc='',
            init='  self->yarrow = NULL;',
            dealloc='Py_DECREF (self->yarrow);')
        self.add_member(
            name='shared_yarrow',
            decl='int shared_yarrow',
            alloc='',
            init='  self->shared_yarrow = 0;')

        self.add_method('save_key',
                        docs='Save key to file (der)',
                        args='METH_VARARGS',
                        body='''
    char *path;
    if (! PyArg_ParseTuple (args, "s", &path))
    {
        return NULL;
    }
    if (! write_object_to_file (pubkey_to_der (self->pub), path))
    {
        PyErr_Format (RSAError, "Failed to write file");
        return NULL;
    }
    Py_RETURN_NONE;
''')

        self.add_method('read_key',
                        docs='Read key from file (der or pem)',
                        args='METH_VARARGS',
                        body='''
    char *path;
    if (! PyArg_ParseTuple (args, "s", &path))
    {
        return NULL;
    }
    if ((self->pub = get_public_key_from_file (read_file (path))) == NULL)
    {
        PyErr_Format (RSAError, "Failed to read file");
        return NULL;
    }
    Py_RETURN_NONE;
''')

        self.add_method('read_key_from_cert',
                        docs='Read key from certificate file (der or pem)',
                        args='METH_VARARGS',
                        body='''
    char *path;
    if (! PyArg_ParseTuple (args, "s", &path))
    {
        return NULL;
    }
    if ((self->pub = get_public_key_from_certfile (read_file (path))) == NULL)
    {
        PyErr_Format (RSAError, "Failed to read file");
        return NULL;
    }
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

        self.add_method(
            name='verify',
            args='METH_VARARGS',
            docs='Verify a signature',
            body=verifybody)

        self.add_to_init_body('''
  PyObject *obj = NULL;
  pynettle_Yarrow *yarrow;

  if (! PyArg_ParseTuple(args, "|O", &obj))
  {
    return -1;
  }
  if (obj != NULL)
  {
    if (PyObject_TypeCheck (obj, &pynettle_Yarrow_Type))
    {
      yarrow = (pynettle_Yarrow *)obj;
      self->yarrow = yarrow;
      Py_INCREF(self->yarrow);
    }
    else
    {
      PyErr_Format (PyExc_TypeError, "Expected Yarrow object");
      return -1;
    }
  }
  else
  {
    self->yarrow = (pynettle_Yarrow *) PyObject_CallObject(
         (PyObject *)& pynettle_Yarrow_Type, NULL);
  }
''')
