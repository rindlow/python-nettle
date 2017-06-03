from CClass import CClass
from textwrap import dedent


class Cipher(CClass):

    def __init__(self, name, family=None, docs=None, lenparam=False,
                 twofuncs=False, twokeys=False, invert=False, mode=None):
        CClass.__init__(self, name, docs)

        if mode is None:
            self.name = name
        else:
            self.name = '{}_{}'.format(name, mode)
        self.family = family
        self.mode = mode
        if lenparam:
            keylen = 'key.len, '
        else:
            keylen = ''

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
            if twokeys:
                self.add_bufferparse_to_init(['encrypt_key', 'decrypt_key',
                                              'iv'])
                self.add_to_init_body(
                    '  if (encrypt_key.buf != NULL) {{\n'
                    '    {name}_set_encrypt_key(self->ctx,'
                    ' encrypt_key.buf);\n'
                    '  }}\n'
                    '  if (decrypt_key.buf != NULL) {{\n'
                    '    {name}_set_decrypt_key(self->ctx,'
                    ' decrypt_key.buf);\n'
                    '  }}\n'.format(name=name))
            else:
                self.add_bufferparse_to_init(['key', 'iv'])
                self.add_to_init_body(
                    '  if (key.buf != NULL) {{\n'
                    '    {name}_set_key(self->ctx, key.buf);\n'
                    '  }}\n'.format(name=name))

            self.add_to_init_body(
                '  if (iv.buf != NULL) {{\n'
                '    memcpy(self->iv, iv.buf, {}_BLOCK_SIZE);\n'
                '  }} \n'.format(family.upper()))
        elif mode == 'ctr':
            self.add_member(
                name='ctr',
                decl='uint8_t ctr[{}_BLOCK_SIZE];'.format(family.upper()))
            if twokeys:
                self.add_bufferparse_to_init(['encrypt_key', 'decrypt_key',
                                              'ctr'])
                self.add_to_init_body(
                    '  if (encrypt_key.buf != NULL) {{\n'
                    '    {name}_set_encrypt_key(self->ctx,'
                    ' encrypt_key.buf);\n'
                    '  }}\n'
                    '  if (decrypt_key.buf != NULL) {{\n'
                    '    {name}_set_decrypt_key(self->ctx,'
                    ' decrypt_key.buf);\n'
                    '  }}\n'.format(name=name))
            else:
                self.add_bufferparse_to_init(['key', 'ctr'])
                self.add_to_init_body(
                    '  if (key.buf != NULL) {{\n'
                    '    {name}_set_key(self->ctx, key.buf);\n'
                    '  }}\n'.format(name=name))
            self.add_to_init_body(
                '  if (ctr.buf != NULL) {{\n'
                '    memcpy(self->ctr, ctr.buf, {}_BLOCK_SIZE);\n'
                '  }} \n'.format(family.upper()))
        else:
            if twokeys:
                self.add_bufferparse_to_init(['encrypt_key', 'decrypt_key'])
                self.add_to_init_body(
                    '  if (encrypt_key.buf != NULL) {{\n'
                    '    {name}_set_encrypt_key(self->ctx,'
                    ' encrypt_key.buf);\n'
                    '  }}\n'
                    '  if (decrypt_key.buf != NULL) {{\n'
                    '    {name}_set_decrypt_key(self->ctx,'
                    ' decrypt_key.buf);\n'
                    '  }}\n'.format(name=name))
            else:
                self.add_bufferparse_to_init(['key'])
                self.add_to_init_body(
                    '  if (key.buf != NULL) {{\n'
                    '    {name}_set_key(self->ctx, {keylen}key.buf);\n'
                    '  }}\n'.format(name=name, keylen=keylen))

        self.add_member(
            name='key_size',
            decl='int key_size',
            init='self->key_size = {}_KEY_SIZE;'.format(name.upper()),
            docs='The size of a {} key'.format(name.upper()),
            flags='READONLY',
            type='T_INT',
            public=True)

        if family is not None:
            self.add_member(
                name='block_size',
                decl='int block_size',
                init='self->block_size = {}_BLOCK_SIZE;'
                .format(family.upper()),
                docs='The internal block size of {}'.format(family.upper()),
                flags='READONLY',
                type='T_INT',
                public=True)

        if twokeys:
            self.add_set_key_function(name, keylen=keylen, usage='encrypt')
            self.add_set_key_function(name, keylen=keylen, usage='decrypt')
        else:
            self.add_set_key_function(name, keylen=keylen)

        if twofuncs:
            self.add_crypt_method(name, 'encrypt')
            self.add_crypt_method(name, 'decrypt')
        else:
            self.add_crypt_method(name, 'crypt')

        if invert:
            self.add_method(
                name='invert_key',
                args='METH_NOARGS',
                docs='On an instance initialized for encryption, initializes'
                ' the context for decryption using the same key',
                body=dedent('''
                    {name}_invert_key(self->ctx, self->ctx);
                    Py_RETURN_NONE;
                    ''').format(name=name))

    def add_bufferparse_to_init(self, buffers):
        self.add_to_init_body(dedent('''
              static char *kwlist[] = {kwlist};
            #if PY_MAJOR_VERSION >= 3
              Py_buffer {vars};
            #else
              nettle_py2buf {vars};
            #endif
              {nullify}
            #if PY_MAJOR_VERSION >= 3
              if (! PyArg_ParseTupleAndKeywords(args, kwds, "{py3fmt}", kwlist,
                                                {py3pointers}))
            #else
              if (! PyArg_ParseTupleAndKeywords(args, kwds, "{py2fmt}", kwlist,
                                                {py2pointers}))
            #endif
              {{
                return -1;
              }}
            ''').format(kwlist='{{"{}", NULL}}'.format('", "'.join(buffers)),
                        vars=', '.join(buffers),
                        nullify='\n  '.join(['{}.buf = NULL;'.format(b)
                                             for b in buffers]),
                        py2fmt='|' + 't#' * len(buffers),
                        py3fmt='|' + 'y*' * len(buffers),
                        py2pointers=',\n\t\t\t\t    '.join(
                            ['&{b}.buf, &{b}.len'.format(b=b)
                             for b in buffers]),
                        py3pointers=', '.join(['&{}'.format(b)
                                               for b in buffers])))

    def add_crypt_method(self, name, func):
        if self.mode == 'cbc':
            crypt = 'cbc_encrypt(self->ctx,' \
                    ' (nettle_cipher_func *)&{name}_{{func}},'\
                    ' {FAMILY}_BLOCK_SIZE,' \
                    ' self->iv, buffer.len, dst, buffer.buf);\n'\
                    .format(name=name, FAMILY=self.family.upper())
        elif self.mode == 'ctr':
            crypt = 'ctr_crypt(self->ctx,' \
                    ' (nettle_cipher_func *)&{name}_{{func}},' \
                    ' {FAMILY}_BLOCK_SIZE,'\
                    ' self->ctr, buffer.len, dst, buffer.buf);'\
                    .format(name=name, FAMILY=self.family.upper())
        else:
            crypt = '{}_{{func}}(self->ctx, buffer.len, dst, buffer.buf);'\
                    .format(name)

        self.add_method(
            name=func,
            args='METH_VARARGS',
            docs='{} data, the length of which must be an'
            ' integral multiple of the block size'.format(name.capitalize()),
            body=dedent('''
                  uint8_t *dst;
                #if PY_MAJOR_VERSION >= 3
                  Py_buffer buffer;
                  if (! PyArg_ParseTuple(args, "y*", &buffer)) {{
                #else
                  nettle_py2buf buffer;
                  if (! PyArg_ParseTuple(args, "t#",
                                         &buffer.buf, &buffer.len)) {{
                #endif
                    return NULL;
                  }}
                  if ((dst = PyMem_Malloc(buffer.len)) == NULL) {{
                    return PyErr_NoMemory();
                  }}
                  {}
                  return PyBytes_FromStringAndSize((const char *)dst,
                                                   buffer.len);
                ''').format(crypt.format(func=func)))

    def add_set_key_function(self, name, keylen, usage=None):
        if usage is None:
            funcname = 'set_key'
            docs = 'Initialize the cipher'
        else:
            funcname = 'set_{}_key'.format(usage)
            docs = 'Initialize the cipher for {}ion'.format(usage)

        self.add_method(
            name=funcname,
            args='METH_VARARGS',
            docs=docs,
            body=dedent('''
                #if PY_MAJOR_VERSION >= 3
                  Py_buffer key;
                  if (! PyArg_ParseTuple(args, "y*", &key)) {{
                #else
                  nettle_py2buf key;
                  if (! PyArg_ParseTuple(args, "t#", &key.buf, &key.len)) {{
                #endif
                    return NULL;
                  }}
                  {name}_{funcname}(self->ctx, {keylen}key.buf);
                  Py_RETURN_NONE;
                ''').format(name=name, funcname=funcname, keylen=keylen))
