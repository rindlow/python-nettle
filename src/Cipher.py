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

from CClass import CClass


class Cipher(CClass):

    def __init__(self, name, family=None, docs=None, lenparam=False,
                 twofuncs=False, twokeys=False, invert=False, varkey=False,
                 mode=None):
        CClass.__init__(self, name, docs)

        self.name = name
        self.family = family
        if lenparam:
            keylen = 'key.len, '
        else:
            keylen = ''
        if twofuncs:
            encrypt_func = '{}_encrypt'.format(self.name)
            decrypt_func = '{}_decrypt'.format(self.name)
        else:
            encrypt_func = '{}_crypt'.format(self.name)
            decrypt_func = '{}_crypt'.format(self.name)

        self.add_member(
            name='is_initialized',
            decl='int is_initialized',
            init='self->is_initialized = 0;')
        self.add_member(
            name='ctx',
            decl='struct {}_ctx *ctx'.format(name),
            alloc='''
                if ((self->ctx = PyMem_Malloc (sizeof (struct {}_ctx))) \\
                    == NULL)
                  {{
                    return PyErr_NoMemory ();
                  }}'''.format(name),
            dealloc='PyMem_Free (self->ctx);\nself->ctx = NULL;')
        self.add_member(
            name='encrypt_func',
            decl='nettle_cipher_func *encrypt_func',
            init='self->encrypt_func = (nettle_cipher_func *)&{};'
            .format(encrypt_func))
        self.add_member(
            name='decrypt_func',
            decl='nettle_cipher_func *decrypt_func',
            init='self->decrypt_func = (nettle_cipher_func *)&{};'
            .format(decrypt_func))

        if twokeys:
            keys = ['encrypt_key', 'decrypt_key']
            self.args = 'encrypt_key=None, decrypt_key=None'
        else:
            keys = ['key']
            self.args = 'key=None'
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
                body='''
                    {name}_invert_key (self->ctx, self->ctx);
                    Py_RETURN_NONE;
                    '''.format(name=name))

    def add_crypt_method(self, name, func):
        crypt = '{}_{{func}} (self->ctx, buffer.len, dst, buffer.buf);'\
                .format(name)

        self.add_method(
            name=func,
            args='METH_VARARGS',
            docs='{} data, the length of which must be an'
            ' integral multiple of the block size'.format(name.capitalize()),
            docargs='bytes',
            body='''
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
                '''.format(crypt.format(func=func)))

    def add_set_key_function(self, name, key='key', keylen='',
                             usage='crypt', mode='ecb',
                             cipher_name='', varkey=False):
        docs = 'Initialize the cipher'
        gsk = ''

        self.add_method(
            name='set_{}'.format(key),
            args='METH_VARARGS',
            docs=docs,
            docargs=key,
            body='''
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
            '''.format(key=key,
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
    
