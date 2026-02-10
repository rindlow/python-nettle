# -*- coding: utf-8 -*-
#
# Cipher.py
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

from c_class import CClass
from params import CipherParam


class Cipher(CClass):

    def __init__(self, param: CipherParam) -> None:
        CClass.__init__(self, param['name'], param['docstring'])

        self.name = param['name']
        self.lname = self.name.lower()
        self.family: str | None = param.get('family')
        self.docs = param['docstring']
        self.required = 1

        if param.get('lenparam'):
            keylen = 'key.len, '
        else:
            keylen = ''
        if param.get('twofuncs'):
            encrypt_func = f'{self.lname}_encrypt'
            decrypt_func = f'{self.lname}_decrypt'
        else:
            encrypt_func = f'{self.lname}_crypt'
            decrypt_func = f'{self.lname}_crypt'

        self.add_member(
            name='is_initialized',
            decl='int is_initialized',
            init='self->is_initialized = 0;')
        self.add_member(
            name='ctx',
            decl=f'struct {self.lname}_ctx *ctx',
            alloc=f'''
                if ((self->ctx = PyMem_Malloc (sizeof (struct {self.lname}_ctx))) \\
                    == NULL)
                  {{
                    return PyErr_NoMemory ();
                  }}''',
            dealloc='PyMem_Free (self->ctx);\nself->ctx = NULL;')
        self.add_member(
            name='encrypt_func',
            decl='nettle_cipher_func *encrypt_func',
            init=f'self->encrypt_func = (nettle_cipher_func *)&{encrypt_func};',
            )
        self.add_member(
            name='decrypt_func',
            decl='nettle_cipher_func *decrypt_func',
            init=f'self->decrypt_func = (nettle_cipher_func *)&{decrypt_func};',
            )

        if param.get('twokeys'):
            keys = ['encrypt_key', 'decrypt_key']
            self.args = 'encrypt_key=None, decrypt_key=None'
        else:
            keys = ['key']
            self.args = 'key=None'
        if param.get('nonce'):
            keys.append('nonce')
            self.args += ', nonce=None'

        self.add_bufferparse_to_init(keys)
        for key in keys:
            if key == 'nonce':
                kl = ''
            else:
                kl = keylen
            self.add_to_init_body(
                self.key_len_check_and_set(
                    key=key, keylen=kl, cipher_name=self.lname, init=True,
                    varkey=param.get('variable_keylen', False)))

        self.add_member(
            name='key_size',
            decl='int key_size',
            init=f'self->key_size = {self.name.upper()}_KEY_SIZE;',
            docs=f'The size of a {self.name.upper()} key',
            flags='READONLY',
            ctype='T_INT',
            public=True)

        if 'stream' not in param:
            if self.family is not None:
                s = self.family.upper()
            else:
                s = self.name.upper()
            self.add_member(
                name='block_size',
                decl='int block_size',
                init=f'self->block_size = {s}_BLOCK_SIZE;',
                docs=f'The internal block size of {s}',
                flags='READONLY',
                ctype='T_INT',
                public=True)

        if param.get('nonce'):
            self.add_member(
                name='nonce_size',
                decl='int nonce_size',
                init=f'self->nonce_size = {self.name.upper()}_NONCE_SIZE;'
                     ,
                docs=f'The size of a {self.name} nonce',
                flags='READONLY',
                ctype='T_INT',
                public=True)

        if param.get('twokeys'):
            self.add_set_key_function(self.name, key='encrypt_key',
                                      keylen=keylen,
                                      varkey=param.get('variable_keylen', False))
            self.add_set_key_function(self.name, key='decrypt_key',
                                      keylen=keylen,
                                      varkey=param.get('variable_keylen', False))
        else:
            self.add_set_key_function(self.name, keylen=keylen,
                                      varkey=param.get('variable_keylen', False))
            self.add_method_alias(alias='set_encrypt_key', method='set_key',
                                  args='METH_VARARGS', docargs='key',
                                  docs='an alias for set_key')
            self.add_method_alias(alias='set_decrypt_key', method='set_key',
                                  args='METH_VARARGS', docargs='key',
                                  docs='an alias for set_key')
        if param.get('nonce'):
            self.required += 1
            self.add_set_key_function(self.name, keylen='', key='nonce')

        if param.get('twofuncs'):
            self.add_crypt_method(self.name, 'encrypt')
            self.add_crypt_method(self.name, 'decrypt')
        else:
            self.add_crypt_method(self.name, 'crypt')
            self.add_method_alias(alias='encrypt', method='crypt',
                                  args='METH_VARARGS', docargs='bytes',
                                  docs='an alias for crypt')
            self.add_method_alias(alias='decrypt', method='crypt',
                                  args='METH_VARARGS', docargs='bytes',
                                  docs='an alias for crypt')

        if param.get('invert'):
            self.add_method(
                name='invert_key',
                args='METH_NOARGS',
                docs='On an instance initialized for encryption, initializes'
                ' the context for decryption using the same key',
                body=f'''
                    {self.lname}_invert_key (self->ctx, self->ctx);
                    Py_RETURN_NONE;
                    ''')

        if param.get('parity'):
            self.add_method(
                name='check_parity',
                args='METH_VARARGS',
                docs='Checks that the given key has correct, odd, parity.'
                     ' Returns True for correct parity, and False for bad'
                     ' parity.',
                docargs='key',
                body=f'''
                      Py_buffer key;
                      if (!PyArg_ParseTuple (args, "y*", &key))
                        {{
                          return NULL;
                        }}
                      return PyBool_FromLong ({self.family}_check_parity(key.len, \\
                          key.buf));
                ''')
            self.add_method(
                name='fix_parity',
                args='METH_VARARGS',
                docs='Adjusts the parity bits to match requirements. You'
                     ' need this function if you have created a'
                     ' random-looking string by a key agreement protocol,'
                     ' and want to use it as a key',
                docargs='key',
                body=f'''
                      Py_buffer key;
                      if (!PyArg_ParseTuple (args, "y*", &key))
                        {{
                          return NULL;
                        }}
                    {self.family}_fix_parity(key.len, key.buf, key.buf);
                    return PyBytes_FromStringAndSize ((const char *)key.buf, \\
                        key.len);
                ''')

        if param.get('keywrap'):
            self.add_method(
                name='keywrap',
                args='METH_VARARGS',
                docs='wrap key, the length of which must be an'
                ' integral multiple of the block size',
                docargs='bytes',
                body=f'''
                    if (self->is_initialized < {self.required})
                        {{
                        PyErr_Format (NotInitializedError,
                                        "Cipher not initialized. Set key first!");
                        return NULL;
                        }}
                    uint8_t *dst;
                    Py_buffer buffer;
                    if (!PyArg_ParseTuple (args, "y*", &buffer))
                        {{
                        return NULL;
                        }}
                    if (buffer.len % 8 != 0)
                    {{
                        PyErr_Format (DataLenError, //
                                    "Data length %d not a multiple of 8", //
                                    buffer.len);
                        return NULL;
                    }}
                    int dstlen = buffer.len + 8;
                    if ((dst = PyMem_Malloc (dstlen)) == NULL)
                        {{
                        return PyErr_NoMemory ();
                        }}
                    nist_keywrap16 (self->ctx, (nettle_cipher_func *) &{self.lname}_encrypt,
                                    (const uint8_t *)"\\xA6\\xA6\\xA6\\xA6\\xA6\\xA6\\xA6\\xA6",
                                    dstlen, dst, buffer.buf);
                    return PyBytes_FromStringAndSize ((const char *) dst,
                                                    dstlen);
                    ''')
            self.add_method(
                name='keyunwrap',
                args='METH_VARARGS',
                docs='unwrap key, the length of which must be an'
                ' integral multiple of the block size',
                docargs='bytes',
                body=f'''
                    if (self->is_initialized < {self.required})
                        {{
                        PyErr_Format (NotInitializedError,
                                        "Cipher not initialized. Set key first!");
                        return NULL;
                        }}
                    uint8_t *dst;
                    Py_buffer buffer;
                    if (!PyArg_ParseTuple (args, "y*", &buffer))
                        {{
                        return NULL;
                        }}
                    if (buffer.len % 8 != 0)
                    {{
                        PyErr_Format (DataLenError, //
                                    "Data length %d not a multiple of 8", //
                                    buffer.len);
                        return NULL;
                    }}
                    int dstlen = buffer.len - 8;
                    if ((dst = PyMem_Malloc (dstlen)) == NULL)
                    {{
                        return PyErr_NoMemory ();
                    }}
                    if (nist_keyunwrap16 (self->ctx, (nettle_cipher_func *) &{self.lname}_decrypt,
                                    (const uint8_t *)"\\xA6\\xA6\\xA6\\xA6\\xA6\\xA6\\xA6\\xA6",
                                    dstlen, dst, buffer.buf))
                    {{
                        return PyBytes_FromStringAndSize ((const char *) dst,
                                                           dstlen);
                    }}
                    else
                    {{
                        PyErr_Format (AuthenticationError, //
                                      "Key unwrapping failed to authenticate");
                        return NULL;
                    }}
                    ''')

    def add_crypt_method(self, name: str, func: str) -> None:
        crypt = f'{self.lname}_{func} (self->ctx, buffer.len, dst, buffer.buf);'

        if self.family is None:
            blockcheck = ''
        else:
            blockcheck = f'''
                if (buffer.len % {self.family.upper()}_BLOCK_SIZE != 0)
                  {{
                    PyErr_Format (DataLenError, //
                                  "Data length %d not a multiple of block" //
                                  " size %d", //
                                   buffer.len, {self.family.upper()}_BLOCK_SIZE);
                    return NULL;
                  }}
            '''

        self.add_method(
            name=func,
            args='METH_VARARGS',
            docs=f'{name.capitalize()} data, the length of which must be an'
            ' integral multiple of the block size',
            docargs='bytes',
            body=f'''
                  if (self->is_initialized < {self.required})
                    {{
                      PyErr_Format (NotInitializedError,
                                    "Cipher not initialized. Set key first!");
                      return NULL;
                    }}
                  uint8_t *dst;
                  Py_buffer buffer;
                  if (!PyArg_ParseTuple (args, "y*", &buffer))
                    {{
                      return NULL;
                    }}
                  {blockcheck}
                  if ((dst = PyMem_Malloc (buffer.len)) == NULL)
                    {{
                      return PyErr_NoMemory ();
                    }}
                  {crypt}
                  return PyBytes_FromStringAndSize ((const char *) dst,
                                                   buffer.len);
                ''')

    def add_set_key_function(self, name: str, key: str = 'key', keylen: str = '',
                             varkey: bool = False) -> None:
        docs = 'Initialize the cipher'
        gsk = ''

        self.add_method(
            name=f'set_{key}',
            args='METH_VARARGS',
            docs=docs,
            docargs=key,
            body='''
                  Py_buffer {key};
                  if (!PyArg_ParseTuple (args, "y*", &{key}))
                    {{
                      return NULL;
                    }}
                {setkey}
                Py_RETURN_NONE;
            '''.format(key=key,
                       setkey=self.key_len_check_and_set(
                           key=key,
                           varkey=varkey,
                           keylen=keylen,
                           key_init=gsk,
                           cipher_name=name.lower())))

    @staticmethod
    def key_len_check_and_set(key: str, varkey: bool = False, keylen: str = '',
                              cipher_name: str = '', key_init: str = '',
                              init: bool = False) -> str:
        if init:
            errval = -1
        else:
            errval = 'NULL'
        if key == 'nonce':
            key_nonce = 'NONCE'
        else:
            key_nonce = 'KEY'
        if varkey:
            check = (f'{key}.len < {cipher_name.upper()}_MIN_{key_nonce}_SIZE || '
                     f'{key}.len > {cipher_name.upper()}_MAX_{key_nonce}_SIZE')

            error = (f'"Invalid {key} length %d, expected between %d and %d.",'
                     f'{key}.len, {cipher_name.upper()}_MIN_{key_nonce}_SIZE, '
                     f'{cipher_name.upper()}_MAX_{key_nonce}_SIZE')
        else:
            check = f'{key}.len != {cipher_name.upper()}_{key_nonce}_SIZE'

            error = (f'"Invalid {key} length %d, expected %d.",'
                     f'{key}.len, {cipher_name.upper()}_{key_nonce}_SIZE')

        return  f'''  if ({key}.buf != NULL)
                {{
                  if ({check})
                    {{
                      PyErr_Format (KeyLenError, {error});
                      return {errval};
                    }}
                  {cipher_name}_set_{key} (self->ctx, {keylen}{key}.buf);
                  {key_init}
                  self->is_initialized += 1;
                }}'''
