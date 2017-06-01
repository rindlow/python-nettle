from CClass import CClass


class Cipher(CClass):

    def __init__(self, name, family, mode, docs):
        CClass.__init__(self, name, docs)
        self.name = '{}_{}'.format(name, mode)

        self.add_member(
            name='ctx',
            decl='struct {}_ctx *ctx'.format(name),
            alloc='if ((self->ctx = PyMem_Malloc(sizeof(struct {}_ctx)))'
            ' == NULL) {{\n    return PyErr_NoMemory();\n  }}'
            .format(name),
            dealloc='PyMem_Free(self->ctx);\n  self->ctx = NULL;')
        if mode == 'cbc':
            self.add_member(
                name='iv',
                decl='uint8_t iv[{}_BLOCK_SIZE];'.format(family.upper()))
            self.add_to_init_body('''
  static char *kwlist[] = {"encrypt_key", "decrypt_key", "iv",  NULL};
#if PY_MAJOR_VERSION >= 3
  Py_buffer encrypt_key, decrypt_key, iv;
#else
  nettle_py2buf encrypt_key, decrypt_key, iv;
#endif
  encrypt_key.buf = NULL;
  decrypt_key.buf = NULL;
  iv.buf = NULL;
#if PY_MAJOR_VERSION >= 3
  if (! PyArg_ParseTupleAndKeywords(args, kwds, "|y*y*y*", kwlist,
                                    &encrypt_key, &decrypt_key, &iv)) {
#else
  if (! PyArg_ParseTupleAndKeywords(args, kwds, "|t#t#t#", kwlist,
                                    &encrypt_key.buf, &encrypt_key.len,
                                    &decrypt_key.buf, &decrypt_key.len,
                                    &iv.buf,  &iv.len)) {
#endif
  return -1;
}''')
            self.add_to_init_body(
                '  if (iv.buf != NULL) {{\n'
                '    memcpy(self->iv, iv.buf, {}_BLOCK_SIZE);\n'
                '  }} \n'.format(family.upper()))
        elif mode == 'ctr':
            self.add_member(
                name='ctr',
                decl='uint8_t ctr[{}_BLOCK_SIZE];'.format(family.upper()))
            self.add_to_init_body('''
  static char *kwlist[] = {"encrypt_key", "decrypt_key", "ctr",  NULL};
#if PY_MAJOR_VERSION >= 3
  Py_buffer encrypt_key, decrypt_key, ctr;
#else
  nettle_py2buf encrypt_key, decrypt_key, ctr;
#endif
  encrypt_key.buf = NULL;
  decrypt_key.buf = NULL;
  ctr.buf = NULL;
#if PY_MAJOR_VERSION >= 3
  if (! PyArg_ParseTupleAndKeywords(args, kwds, "|y*y*y*", kwlist,
                                    &encrypt_key, &decrypt_key, &ctr)) {
#else
  if (! PyArg_ParseTupleAndKeywords(args, kwds, "|t#t#t#", kwlist,
                                    &encrypt_key.buf, &encrypt_key.len,
                                    &decrypt_key.buf, &decrypt_key.len,
                                    &ctr.buf,  &ctr.len)) {
#endif
  return -1;
}''')
            self.add_to_init_body(
                '  if (ctr.buf != NULL) {{\n'
                '    memcpy(self->ctr, ctr.buf, {}_BLOCK_SIZE);\n'
                '  }} \n'.format(family.upper()))
        else:
            self.add_to_init_body('''
  static char *kwlist[] = {"encrypt_key", "decrypt_key", NULL};
#if PY_MAJOR_VERSION >= 3
  Py_buffer encrypt_key, decrypt_key;
#else
  nettle_py2buf encrypt_key, decrypt_key;
#endif
  encrypt_key.buf = NULL;
  decrypt_key.buf = NULL;
#if PY_MAJOR_VERSION >= 3
  if (! PyArg_ParseTupleAndKeywords(args, kwds, "|y*y*", kwlist,
                                    &encrypt_key, &decrypt_key)) {
#else
  if (! PyArg_ParseTupleAndKeywords(args, kwds, "|t#t#", kwlist,
                                    &encrypt_key.buf, &encrypt_key.len,
                                    &decrypt_key.buf, &decrypt_key.len)) {
#endif
  return -1;
}''')
        self.add_to_init_body(
            '  if (encrypt_key.buf != NULL) {{\n'
            '    {name}_set_encrypt_key(self->ctx,'
            ' encrypt_key.buf);\n'
            '  }}\n'
            '  if (decrypt_key.buf != NULL) {{\n'
            '    {name}_set_decrypt_key(self->ctx,'
            ' decrypt_key.buf);\n'
            '  }}\n'.format(name=name))
        self.add_member(
            name='key_size',
            decl='int key_size',
            init='self->key_size = {}_KEY_SIZE;'.format(name.upper()),
            docs='The size of a {} key'.format(name.upper()),
            flags='READONLY',
            type='T_INT',
            public=True)
        self.add_member(
            name='block_size',
            decl='int block_size',
            init='self->block_size = {}_BLOCK_SIZE;'.format(family.upper()),
            docs='The internal block size of {}'.format(family.upper()),
            flags='READONLY',
            type='T_INT',
            public=True)

        self.add_method(
            name='set_encrypt_key',
            args='METH_VARARGS',
            docs='Initialize the cipher for encryption',
            body='''
#if PY_MAJOR_VERSION >= 3
  Py_buffer encrypt_key;
  if (! PyArg_ParseTuple(args, "y*", &encrypt_key)) {{
#else
  nettle_py2buf encrypt_key;
  if (! PyArg_ParseTuple(args, "t#", &encrypt_key.buf, &encrypt_key.len)) {{
#endif
    return NULL;
  }}
  {name}_set_encrypt_key(self->ctx, encrypt_key.buf);
  Py_RETURN_NONE;
'''.format(name=name))

        self.add_method(
            name='set_decrypt_key',
            args='METH_VARARGS',
            docs='Initialize the cipher for decryption',
            body='''
#if PY_MAJOR_VERSION >= 3
  Py_buffer decrypt_key;
  if (! PyArg_ParseTuple(args, "y*", &decrypt_key)) {{
#else
  nettle_py2buf decrypt_key;
  if (! PyArg_ParseTuple(args, "t#", &decrypt_key.buf, &decrypt_key.len)) {{
#endif
    return NULL;
  }}
  {name}_set_decrypt_key(self->ctx, decrypt_key.buf);
  Py_RETURN_NONE;
'''.format(name=name))

        if mode == 'ecb':
            crypt = '{}_{{func}}(self->ctx, buffer.len, dst, buffer.buf);'\
                    .format(name)
        elif mode == 'cbc':
            crypt = 'cbc_encrypt(self->ctx,' \
                    ' (nettle_cipher_func *)&{name}_{{func}},'\
                    ' {FAMILY}_BLOCK_SIZE,' \
                    ' self->iv, buffer.len, dst, buffer.buf);\n'\
                    .format(name=name, FAMILY=family.upper())
        elif mode == 'ctr':
            crypt = 'ctr_crypt(self->ctx,' \
                    ' (nettle_cipher_func *)&{name}_{{func}},' \
                    ' {FAMILY}_BLOCK_SIZE,'\
                    ' self->ctr, buffer.len, dst, buffer.buf);'\
                    .format(name=name, FAMILY=family.upper())

        if name[:8] == 'camellia':
            func = 'crypt'
        else:
            func = 'encrypt'
        self.add_method(
            name='encrypt',
            args='METH_VARARGS',
            docs='Encrypt data, the length of which must be an integral'
            ' multiple of the block size',
            body='''
  uint8_t *dst;
#if PY_MAJOR_VERSION >= 3
  Py_buffer buffer;
  if (! PyArg_ParseTuple(args, "y*", &buffer)) {{
#else
  nettle_py2buf buffer;
  if (! PyArg_ParseTuple(args, "t#", &buffer.buf, &buffer.len)) {{
#endif
    return NULL;
  }}
  if ((dst = PyMem_Malloc(buffer.len)) == NULL) {{
    return PyErr_NoMemory();
  }}
  {}
  return PyBytes_FromStringAndSize((const char *)dst, buffer.len);
'''.format(crypt.format(func=func)))

        if name[:8] == 'camellia':
            func = 'crypt'
        else:
            func = 'decrypt'
        self.add_method(
            name='decrypt',
            args='METH_VARARGS',
            docs='Encrypt data, the length of which must be an integral'
            ' multiple of the block size',
            body='''
  uint8_t *dst;
#if PY_MAJOR_VERSION >= 3
  Py_buffer buffer;
  if (! PyArg_ParseTuple(args, "y*", &buffer)) {{
#else
  nettle_py2buf buffer;
  if (! PyArg_ParseTuple(args, "t#", &buffer.buf, &buffer.len)) {{
#endif
    return NULL;
  }}
  if ((dst = PyMem_Malloc(buffer.len)) == NULL) {{
    return PyErr_NoMemory();
  }}
  {}
  return PyBytes_FromStringAndSize((const char *)dst, buffer.len);
'''.format(crypt.format(func=func)))

        self.add_method(
            name='invert_key',
            args='METH_NOARGS',
            docs='On an instance initialized for encryption, initializes'
            ' the context for decryption using the same key',
            body='''
  {name}_invert_key(self->ctx, self->ctx);
  Py_RETURN_NONE;
    '''.format(name=name))
