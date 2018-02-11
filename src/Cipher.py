from CClass import CClass
from textwrap import dedent


class Cipher(CClass):

    def __init__(self, name, family=None, docs=None, lenparam=False,
                 twofuncs=False, twokeys=False, invert=False, varkey=False,
                 mode=None):
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
            name='is_initialized',
            decl='int is_initialized',
            init='self->is_initialized = 0;')
        self.add_member(
            name='ctx',
            decl='struct {}_ctx *ctx'.format(name),
            alloc='if ((self->ctx = PyMem_Malloc (sizeof (struct {}_ctx)))'
            ' == NULL)\n    {{\n      return PyErr_NoMemory ();\n    }}'
            .format(name),
            dealloc='PyMem_Free (self->ctx);\n  self->ctx = NULL;')
        if mode == 'cbc':
            self.add_member(
                name='iv',
                decl='uint8_t iv[{}_BLOCK_SIZE]'.format(family.upper()))
            if twokeys:
                keys = ['encrypt_key', 'decrypt_key']
            else:
                keys = ['key']
            self.add_bufferparse_to_init(keys + ['iv'])
            for key in keys:
                self.add_to_init_body(
                    self.key_len_check_and_set(
                        key=key, keylen=keylen, cipher_name=name, init=True,
                        varkey=varkey))

            self.add_to_init_body(
                '  if (iv.buf != NULL)\n'
                '    {{\n'
                '      memcpy (self->iv, iv.buf, {}_BLOCK_SIZE);\n'
                '    }}\n'.format(family.upper()))

            self.add_method(
                name='set_iv',
                args='METH_VARARGS',
                docs='argument is a pointer to an Initialization Vector (IV) ',
                body=dedent('''
                    #if PY_MAJOR_VERSION >= 3
                      Py_buffer iv;
                      if (!PyArg_ParseTuple (args, "y*", &iv))
                    #else
                      nettle_py2buf iv;
                      if (!PyArg_ParseTuple (args, "t#", &iv.buf, &iv.len))
                    #endif
                        {{
                          return NULL;
                        }}
                      if (iv.buf != NULL)
                        {{
                          memcpy (self->iv, iv.buf, {FAMILY}_BLOCK_SIZE);
                        }}
                      Py_RETURN_NONE;
                ''').format(name=name, FAMILY=family.upper()))

        elif mode == 'ctr':
            self.add_member(
                name='ctr',
                decl='uint8_t ctr[{}_BLOCK_SIZE]'.format(family.upper()))
            if twokeys:
                keys = ['encrypt_key', 'decrypt_key']
            else:
                keys = ['key']
            self.add_bufferparse_to_init(keys + ['ctr'])
            for key in keys:
                self.add_to_init_body(
                    self.key_len_check_and_set(
                        key=key, keylen=keylen, cipher_name=name, init=True,
                        varkey=varkey))

            self.add_to_init_body(
                '  if (ctr.buf != NULL)\n'
                '    {{\n'
                '      memcpy (self->ctr, ctr.buf, {}_BLOCK_SIZE);\n'
                '    }}\n'.format(family.upper()))
            self.add_method(
                name='set_counter',
                args='METH_VARARGS',
                docs='argument is a pointer to an initial counter) ',
                body=dedent('''
                    #if PY_MAJOR_VERSION >= 3
                      Py_buffer ctr;
                      if (!PyArg_ParseTuple (args, "y*", &ctr))
                    #else
                      nettle_py2buf ctr;
                      if (!PyArg_ParseTuple (args, "t#", &ctr.buf, &ctr.len))
                    #endif
                      {{
                        return NULL;
                      }}
                      if (ctr.buf != NULL)
                        {{
                          memcpy (self->ctr, ctr.buf, {FAMILY}_BLOCK_SIZE);
                        }}
                      Py_RETURN_NONE;
                ''').format(name=name, FAMILY=family.upper()))

        elif mode == 'gcm':
            self.add_member(
                name='gcm_ctx',
                decl='struct gcm_ctx *gcmctx',
                alloc='if ((self->gcmctx = PyMem_Malloc (sizeof (struct'
                ' gcm_ctx))) == NULL)\n'
                '  {\n'
                '    return PyErr_NoMemory ();\n'
                '  }',
                dealloc='PyMem_Free (self->gcmctx);\n  self->gcmctx = NULL;')
            self.add_member(
                name='gcm_key',
                decl='struct gcm_key *gcmkey',
                alloc='if ((self->gcmkey = PyMem_Malloc (sizeof (struct'
                ' gcm_key))) == NULL)\n'
                '  {\n'
                '    return PyErr_NoMemory ();\n'
                '  }',
                dealloc='PyMem_Free (self->gcmkey);\n  self->gcmkey = NULL;')
            if twokeys:
                keys = ['encrypt_key', 'decrypt_key']
            else:
                keys = ['key']
            self.add_bufferparse_to_init(keys + ['iv'])
            for key in keys:
                self.add_to_init_body(
                    self.key_len_check_and_set(
                        key=key, keylen=keylen, cipher_name=name, init=True,
                        varkey=varkey,
                        key_init='gcm_set_key (self->gcmkey,'
                        ' self->ctx, (nettle_cipher_func *)'
                        '&{name}_{usage});'.format(name=name,
                                                   usage=key.split('_')[0])))

            self.add_to_init_body(
                '  if (iv.buf != NULL)\n'
                '    {\n'
                '      gcm_set_iv (self->gcmctx, self->gcmkey, iv.len,'
                ' iv.buf);\n'
                '    } \n')
            self.add_method(
                name='set_iv',
                args='METH_VARARGS',
                docs='argument is a pointer to an Initialization Vector (IV) ',
                body=dedent('''
                   #if PY_MAJOR_VERSION >= 3
                     Py_buffer iv;
                     if (!PyArg_ParseTuple (args, "y*", &iv)) {{
                   #else
                     nettle_py2buf iv;
                     if (!PyArg_ParseTuple (args, "t#", &iv.buf, &iv.len)) {{
                   #endif
                       return NULL;
                     }}
                     if (iv.buf != NULL) {{
                       gcm_set_iv (self->gcmctx, self->gcmkey, iv.len, iv.buf);
                     }}
                     Py_RETURN_NONE;
                ''').format(name=name, FAMILY=family.upper()))

            self.add_method(
                name='update',
                args='METH_VARARGS',
                docs='Provides associated data to be authenticated. If used,'
                ' must be called before encrypt or decrypt. All but the last'
                ' call for each message must use a length that is a multiple'
                ' of the block size.',
                body=dedent('''
                    #if PY_MAJOR_VERSION >= 3
                      Py_buffer buffer;

                      if (!PyArg_ParseTuple (args, "y*", &buffer)) {{
                    #else
                      nettle_py2buf buffer;
                      if (!PyArg_ParseTuple (args, "t#",
                                             &buffer.buf, &buffer.len)) {{
                    #endif
                        return NULL;
                      }}
                      gcm_update (self->gcmctx, self->gcmkey,
                                 buffer.len, buffer.buf);
                      Py_RETURN_NONE;
''').format(name=name))

            self.add_method(
                name='digest',
                args='METH_NOARGS',
                docs='Extracts the message digest (also known as'
                ' \'authentication tag\'). This is the final operation when'
                ' processing a message. It\'s strongly recommended that'
                ' length is GCM_DIGEST_SIZE, but if you provide a smaller'
                ' value, only the first length octets'
                ' of the digest are written.',
                body='''
  uint8_t digest[GCM_DIGEST_SIZE];
  gcm_digest (self->gcmctx, self->gcmkey, self->ctx,
             (nettle_cipher_func *) &{name}_encrypt, GCM_DIGEST_SIZE, digest);
  return PyBytes_FromStringAndSize ((const char *) digest, GCM_DIGEST_SIZE);
'''.format(name=name))

        else:
            # ecb
            if twokeys:
                keys = ['encrypt_key', 'decrypt_key']
            else:
                keys = ['key']
            self.add_bufferparse_to_init(keys)
            for key in keys:
                self.add_to_init_body(
                    self.key_len_check_and_set(
                        key=key, keylen=keylen, cipher_name=name, init=True,
                        varkey=varkey))

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
            self.add_set_key_function(name, key='encrypt_key', keylen=keylen,
                                      mode=mode, usage='encrypt',
                                      cipher_name=name, varkey=varkey)
            self.add_set_key_function(name, key='decrypt_key', keylen=keylen,
                                      mode=mode, usage='decrypt',
                                      cipher_name=name, varkey=varkey)
        else:
            self.add_set_key_function(name, keylen=keylen, mode=mode,
                                      cipher_name=name, varkey=varkey)

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
                    {name}_invert_key (self->ctx, self->ctx);
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
              if (!PyArg_ParseTupleAndKeywords
                      (args, kwds, "{py3fmt}", kwlist, {py3pointers}))
            #else
              if (!PyArg_ParseTupleAndKeywords
                      (args, kwds, "{py2fmt}", kwlist, {py2pointers}))
            #endif
                {{
                  return -1;
                }}
            ''').format(kwlist='{{ "{}", NULL }}'.format('", "'.join(buffers)),
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
            crypt = 'cbc_encrypt (self->ctx,' \
                    ' (nettle_cipher_func *) &{name}_{{func}},'\
                    ' {FAMILY}_BLOCK_SIZE,' \
                    ' self->iv, buffer.len, dst, buffer.buf);\n'\
                    .format(name=name, FAMILY=self.family.upper())
        elif self.mode == 'ctr':
            crypt = 'ctr_crypt (self->ctx,' \
                    ' (nettle_cipher_func *) &{name}_{{func}},' \
                    ' {FAMILY}_BLOCK_SIZE,'\
                    ' self->ctr, buffer.len, dst, buffer.buf);'\
                    .format(name=name, FAMILY=self.family.upper())
        elif self.mode == 'gcm':
            crypt = 'gcm_encrypt (self->gcmctx, self->gcmkey, self->ctx,' \
                    ' (nettle_cipher_func *) &{name}_{{func}},' \
                    ' buffer.len, dst, buffer.buf);'\
                    .format(name=name)
        else:
            crypt = '{}_{{func}} (self->ctx, buffer.len, dst, buffer.buf);'\
                    .format(name)

        self.add_method(
            name=func,
            args='METH_VARARGS',
            docs='{} data, the length of which must be an'
            ' integral multiple of the block size'.format(name.capitalize()),
            body=dedent('''
                  if (!self->is_initialized)
                    {{
                      PyErr_Format (NotInitializedError,
                                    "Cipher not initialized. Set key first!");
                      return NULL;
                    }}
                  uint8_t *dst;
                #if PY_MAJOR_VERSION >= 3
                  Py_buffer buffer;
                  if (!PyArg_ParseTuple (args, "y*", &buffer))
                #else
                  nettle_py2buf buffer;
                  if (!PyArg_ParseTuple (args, "t#",
                                         &buffer.buf, &buffer.len))
                #endif
                    {{
                      return NULL;
                    }}
                  if ((dst = PyMem_Malloc (buffer.len)) == NULL)
                    {{
                      return PyErr_NoMemory ();
                    }}
                  {}
                  return PyBytes_FromStringAndSize ((const char *) dst,
                                                   buffer.len);
                ''').format(crypt.format(func=func)))

    def add_set_key_function(self, name, key='key', keylen='',
                             usage='crypt', mode='ecb',
                             cipher_name='', varkey=False):
        docs = 'Initialize the cipher'
        if mode == 'gcm':
            gsk = 'gcm_set_key (self->gcmkey, self->ctx,' \
                  '(nettle_cipher_func *)&{name}_{usage});' \
                  .format(name=name, usage=usage)
        else:
            gsk = ''

        self.add_method(
            name='set_{}'.format(key),
            args='METH_VARARGS',
            docs=docs,
            body=dedent('''
                #if PY_MAJOR_VERSION >= 3
                  Py_buffer {key};
                  if (!PyArg_ParseTuple (args, "y*", &{key}))
                #else
                  nettle_py2buf {key};
                  if (!PyArg_ParseTuple (args, "t#", &{key}.buf, &{key}.len))
                #endif
                    {{
                      return NULL;
                    }}
                {setkey}  Py_RETURN_NONE;
            ''').format(key=key,
                        setkey=self.key_len_check_and_set(
                            key=key,
                            varkey=varkey,
                            keylen=keylen,
                            key_init=gsk,
                            cipher_name=cipher_name)))

    def key_len_check_and_set(self, key, varkey=False, keylen='',
                              cipher_name='', key_init='', init=False):
        if init:
            errval = -1
        else:
            errval = 'NULL'
        if varkey:
            check = '{key}.len < {cipher_name}_MIN_KEY_SIZE || ' \
                    '{key}.len > {cipher_name}_MAX_KEY_SIZE' \
                    .format(key=key, cipher_name=cipher_name.upper())
            error = '"Invalid key length %d, expected between %d and %d.",' \
                    '{key}.len, {cipher_name}_MIN_KEY_SIZE, ' \
                    '{cipher_name}_MAX_KEY_SIZE' \
                    .format(key=key, cipher_name=cipher_name.upper())
        else:
            check = '{key}.len != {cipher_name}_KEY_SIZE' \
                    .format(key=key, cipher_name=cipher_name.upper())
            error = '"Invalid key length %d, expected %d.",' \
                    '{key}.len, {cipher_name}_KEY_SIZE' \
                    .format(key=key, cipher_name=cipher_name.upper())
        return \
            '  if ({key}.buf != NULL)\n' \
            '    {{\n' \
            '      if ({check})\n' \
            '        {{\n' \
            '          PyErr_Format (KeyLenError, {error});\n' \
            '          return {errval};\n' \
            '        }}\n' \
            '      {cipher_name}_set_{key} (self->ctx, {keylen}{key}.buf);\n' \
            '      {key_init}\n' \
            '      self->is_initialized = 1;\n' \
            '    }}\n' \
            .format(key=key, check=check, error=error, cipher_name=cipher_name,
                    keylen=keylen, errval=errval, key_init=key_init)
