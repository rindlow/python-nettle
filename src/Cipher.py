#!/usr/bin/env python3

from CClass import CClass

class Cipher(CClass):

    def __init__(self, name, family, mode, docs):
        CClass.__init__(self, name, docs)
        self.name = '{}_{}'.format(name, mode)
        
        self.add_member(
            name='ctx',
            decl='struct {}_ctx *ctx'.format(name),
            alloc='if ((self->ctx = PyMem_Malloc(sizeof(struct {}_ctx)))'
            ' == NULL) {{\n    return PyErr_NoMemory();\n  }}'\
            .format(name),
            dealloc='PyMem_Free(self->ctx);\n  self->ctx = NULL;')
        if mode == 'cbc':
            self.add_member(
                name='iv',
                decl='uint8_t iv[{}_BLOCK_SIZE];'.format(family.upper()))
            self.add_to_init_body(
                '  Py_buffer encrypt_key, decrypt_key, iv;\n'
                '  static char *kwlist[] = {"encrypt_key", "decrypt_key",'
                ' "iv",  NULL};\n'
                '  encrypt_key.buf = NULL;\n'
                '  decrypt_key.buf = NULL;\n'
                '  iv.buf = NULL;\n'
                '  if (! PyArg_ParseTupleAndKeywords(args, kwds, "|y*y*y*",'
                ' kwlist, &encrypt_key, &decrypt_key, &iv)) {\n'
                '    return -1;\n'
                '  }\n')
            self.add_to_init_body(
                '  if (iv.buf != NULL) {{\n'
                '    memcpy(self->iv, iv.buf, {}_BLOCK_SIZE);\n'
                '  }} \n'.format(family.upper()))
        elif mode == 'ctr':
            self.add_member(
                name='ctr',
                decl='uint8_t ctr[{}_BLOCK_SIZE];'.format(family.upper()))
            self.add_to_init_body(
                '  Py_buffer encrypt_key, decrypt_key, ctr;\n'
                '  static char *kwlist[] = {"encrypt_key", "decrypt_key",'
                ' "ctr",  NULL};\n'
                '  encrypt_key.buf = NULL;\n'
                '  decrypt_key.buf = NULL;\n'
                '  ctr.buf = NULL;\n'
                '  if (! PyArg_ParseTupleAndKeywords(args, kwds, "|y*y*y*",'
                ' kwlist, &encrypt_key, &decrypt_key, &ctr)) {\n'
                '    return -1;\n'
                '  }\n')
            self.add_to_init_body(
                '  if (ctr.buf != NULL) {{\n'
                '    memcpy(self->ctr, ctr.buf, {}_BLOCK_SIZE);\n'
                '  }} \n'.format(family.upper()))
        else:
            self.add_to_init_body(
                '  Py_buffer encrypt_key, decrypt_key;\n'
                '  static char *kwlist[] = {"encrypt_key", "decrypt_key",'
                '  NULL};\n'
                '  encrypt_key.buf = NULL;\n'
                '  decrypt_key.buf = NULL;\n'
                '  if (! PyArg_ParseTupleAndKeywords(args, kwds, "|y*y*",'
                ' kwlist, &encrypt_key, &decrypt_key)) {\n'
                '    return -1;\n'
                '  }\n')
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

        if mode ==  'ecb':
            crypt = '{}_encrypt(self->ctx, buffer.len, dst, buffer.buf);'\
                    .format(name)
        elif mode == 'cbc':
            crypt = 'cbc_encrypt(self->ctx,' \
                    ' (nettle_cipher_func *)&{name}_{{func}},'\
                    ' {FAMILY}_BLOCK_SIZE,' \
                    ' self->iv, buffer.len, dst, buffer.buf);'\
                .format(name=name, FAMILY=family.upper())
        elif mode == 'ctr':
            crypt = 'ctr_crypt(self->ctx,' \
                    ' (nettle_cipher_func *)&{name}_{{func}},' \
                    ' {FAMILY}_BLOCK_SIZE,'\
            ' self->ctr, buffer.len, dst, buffer.buf);'\
                .format(name=name, FAMILY=family.upper())
            
        self.add_method(
            name='encrypt',
            args='METH_VARARGS',
            docs='Encrypt data, the length of which must be an integral multiple of the block size',
            body='''
  Py_buffer buffer;
  uint8_t *dst;

  if (! PyArg_ParseTuple(args, "y*", &buffer)) {{
    return NULL;
  }}
  if ((dst = PyMem_Malloc(buffer.len)) == NULL) {{
    return PyErr_NoMemory();
  }}
  {}
  return PyBytes_FromStringAndSize((const char *)dst, buffer.len);
'''.format(crypt.format(func='encrypt')))

        self.add_method(
            name='decrypt',
            args='METH_VARARGS',
            docs='Encrypt data, the length of which must be an integral multiple of the block size',
            body='''
  Py_buffer buffer;
  uint8_t *dst;

  if (! PyArg_ParseTuple(args, "y*", &buffer)) {{
    return NULL;
  }}
  if ((dst = PyMem_Malloc(buffer.len)) == NULL) {{
    return PyErr_NoMemory();
  }}
  {}
  return PyBytes_FromStringAndSize((const char *)dst, buffer.len);
'''.format(crypt.format(func='decrypt')))

        self.add_method(
            name='invert_key',
            args='METH_NOARGS',
            docs='On an instance initialized for encryption, initializes the context for decryption using the same key',
            body='''
  {name}_invert_key(self->ctx, self->ctx);
  Py_RETURN_NONE;
    '''.format(name=name))

