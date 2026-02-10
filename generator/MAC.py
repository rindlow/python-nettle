# coding: utf-8
#
# MAC.py
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
from params import MacParam


class MAC(CClass):

    def __init__(self, param: MacParam) -> None:
        CClass.__init__(self, param['name'], param['docstring'])
        name = param['name']
        lname = name.lower()
        uname = name.upper()

        self.add_member(
            name='is_initialized',
            decl='int is_initialized',
            init='self->is_initialized = 0;')
        self.add_member(
            name='ctx',
            decl=f'struct {lname}_ctx *ctx',
            alloc=f'if ((self->ctx = PyMem_Malloc (sizeof (struct {lname}_ctx)))'
            ' == NULL)\n    {\n      return PyErr_NoMemory ();\n    }'
            ,
            dealloc='PyMem_Free (self->ctx);\n  self->ctx = NULL;')

        if 'nonce' not in param:
            digestsize = f'{uname[5:]}_DIGEST_SIZE'
            keylen = 'key.len, '
            self.add_bufferparse_to_init(['key'])
            self.add_to_init_body('  if (key.buf != NULL)\n    {\n'
                                  f'      {lname}_set_key (self->ctx,'
                                  ' key.len, key.buf);\n'
                                  '      self->is_initialized = 1;\n'
                                  '    }\n',
                                  )
            self.args = 'key=None'
        else:
            digestsize = f'{uname}_DIGEST_SIZE'
            keylen = ''
            if param['nonce'] == 'fixed':
                nonce_len = ''
            else:
                nonce_len = 'nonce.len, '
            self.add_bufferparse_to_init(['key', 'nonce'])
            self.args = 'key=None, nonce=None'
            self.add_to_init_body(f'''
                if (key.buf != NULL)
                  {{
                    {lname}_set_key (self->ctx, key.buf);
                    self->is_initialized = 1;
                  }}
                if (nonce.buf != NULL)
                  {{
                    if (!self->is_initialized)
                      {{
                        PyErr_Format (NotInitializedError,
                                      "Cipher not initialized. \\
                                       Set key first!");
                        return -1;
                      }}
                    {lname}_set_nonce (self->ctx, {nonce_len}nonce.buf);
                  }}
            ''')
            self.add_method(
                name='set_nonce',
                args='METH_VARARGS',
                docs='Initializes the MAC with the nonce',
                docargs='nonce',
                body=f'''
                      if (!self->is_initialized)
                        {{
                          PyErr_Format (NotInitializedError,
                                     "Cipher not initialized. Set key first!");
                          return NULL;
                        }}
                      Py_buffer nonce;

                      if (! PyArg_ParseTuple (args, "y*", &nonce))
                        {{
                          return NULL;
                        }}
                      {lname}_set_nonce (self->ctx, {nonce_len}nonce.buf);
                      Py_RETURN_NONE;
                    ''')

        self.add_member(
            name='digest_size',
            decl='int digest_size',
            init=f'self->digest_size = {digestsize};',
            docs=f'The size of a {uname} digest',
            flags='READONLY',
            ctype='T_INT',
            public=True)
        self.add_method(
            name='set_key',
            args='METH_VARARGS',
            docs='Initializes the MAC with the key',
            docargs='key',
            body=f'''
                  Py_buffer key;

                  if (! PyArg_ParseTuple (args, "y*", &key))
                    {{
                      return NULL;
                    }}
                  {lname}_set_key (self->ctx, {keylen}key.buf);
                  self->is_initialized = 1;
                  Py_RETURN_NONE;
                ''')
        self.add_method(
            name='update',
            args='METH_VARARGS',
            docs='Process some more data',
            docargs='msg',
            body=f'''
                  if (!self->is_initialized)
                    {{
                      PyErr_Format (NotInitializedError,
                                    "Cipher not initialized. Set key first!");
                      return NULL;
                    }}
                  Py_buffer buffer;

                  if (! PyArg_ParseTuple (args, "y*", &buffer))
                    {{
                      return NULL;
                    }}
                  {lname}_update (self->ctx, buffer.len, buffer.buf);
                  Py_RETURN_NONE;
                ''')
        self.add_method(
            name='digest',
            args='METH_NOARGS',
            docs='Performs final processing and extracts the message digest',
            body=f'''
                uint8_t digest[{digestsize}];
                struct {lname}_ctx *ctx_copy;

                if (!self->is_initialized)
                  {{
                    PyErr_Format (NotInitializedError,
                                  "Cipher not initialized. Set key first!");
                    return NULL;
                  }}
                if ((ctx_copy = PyMem_Malloc (sizeof \\
                     (struct {lname}_ctx))) == NULL)
                  {{
                    return PyErr_NoMemory ();
                  }}
                memcpy(ctx_copy, self->ctx, sizeof (struct {lname}_ctx));
                {lname}_digest (ctx_copy, digest);
                PyMem_Free(ctx_copy);
                return PyBytes_FromStringAndSize ((const char *) digest, \\
                                                  {digestsize});
            ''')

        self.add_method(
            name='hexdigest',
            args='METH_NOARGS',
            docs='Performs final processing and extracts the message digest'
            ' as a string of hexadecimal characters',
            body=f'''
                uint8_t digest[{digestsize}];
                char hex[{digestsize} * 2 + 1];
                char *ptr = hex;
                struct {lname}_ctx *ctx_copy;

                if (!self->is_initialized)
                  {{
                    PyErr_Format (NotInitializedError,
                                  "Cipher not initialized. Set key first!");
                    return NULL;
                  }}
                if ((ctx_copy = PyMem_Malloc (sizeof \\
                     (struct {lname}_ctx))) == NULL)
                  {{
                    return PyErr_NoMemory ();
                  }}
                memcpy(ctx_copy, self->ctx, sizeof (struct {lname}_ctx));
                {lname}_digest (ctx_copy, digest);
                PyMem_Free(ctx_copy);
                for (int i = 0; i < {digestsize}; i++)
                  {{
                    snprintf(ptr, 3, "%02X", digest[i]);
                    ptr += 2;
                  }}
                return PyUnicode_FromString ((const char *) hex);
            ''')
