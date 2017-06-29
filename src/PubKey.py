from CClass import CClass


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
            decl='struct yarrow256_ctx *yarrow;',
            alloc='',
            init='  self->yarrow = NULL;',
            dealloc='PyMem_Free (self->yarrow);\n  self->yarrow = NULL;')
        self.add_to_init_body('''
    ssize_t res;
    int fd;
    uint8_t seed[YARROW256_SEED_FILE_SIZE];

    if ((self->yarrow = PyMem_Malloc (sizeof (struct yarrow256_ctx))) == NULL)
    {
        PyErr_NoMemory ();
        return -1;
    }
    yarrow256_init (self->yarrow, 0, NULL);
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

    yarrow256_seed (self->yarrow, YARROW256_SEED_FILE_SIZE, seed);''')

        self.add_method('genkey',
                        docs='Generate a new RSA keypair',
                        args='METH_VARARGS',
                        body='''
    int res, n_size, e_size;
    if (! PyArg_ParseTuple(args, "ii", &n_size, &e_size)) {
        return NULL;
    }

    res = rsa_generate_keypair (self->pub, self->key,
                                self->yarrow,
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
        PyErr_Format (RSAError, "Failed to write file");
        return NULL;
    }
    Py_RETURN_NONE;
''')

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
        PyErr_Format (RSAError, "Failed to write file");
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
