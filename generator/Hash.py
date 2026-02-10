# -*- coding: utf-8 -*-
#
# Hash.py
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
from params import HashParam


class Hash(CClass):

    def __init__(self, param: HashParam) -> None:
        name = param['name']
        lname = name.lower()
        uname = name.upper()
        context = param.get('context', f'{lname}_ctx')
        CClass.__init__(self, name, param['docstring'], args='[msg]')

        self.add_to_init_body(f'''
                  Py_buffer buffer;
                  buffer.buf = NULL;
                  if (! PyArg_ParseTuple (args, "|y*", &buffer)) {{
                    return -1;
                  }}
                  if (buffer.buf != NULL) {{
                    {lname}_update (self->ctx, buffer.len, buffer.buf);
                  }}
        ''')

        self.add_member(
            name='ctx',
            decl=f'struct {context} *ctx',
            init=f'{lname}_init (self->ctx);',
            alloc=f'if ((self->ctx = PyMem_Malloc (sizeof (struct {context})))'
            ' == NULL) {\n    return PyErr_NoMemory ();\n  }'
            ,
            dealloc='PyMem_Free (self->ctx);\n  self->ctx = NULL;')
        self.add_member(
            name='digest_size',
            decl='int digest_size',
            init=f'self->digest_size = {uname}_DIGEST_SIZE;',
            docs=f'The size of a {uname} digest',
            flags='READONLY',
            ctype='T_INT',
            public=True)
        self.add_member(
            name='block_size',
            decl='int block_size',
            init=f'self->block_size = {uname}_BLOCK_SIZE;',
            docs=f'The internal block size of {uname}',
            flags='READONLY',
            ctype='T_INT',
            public=True)
        self.add_method(
            name='update',
            args='METH_VARARGS',
            docs='Hash some more data',
            docargs='msg',
            body=f'''
                  Py_buffer buffer;

                  if (! PyArg_ParseTuple (args, "y*", &buffer)) {{
                    return NULL;
                  }}
                  {lname}_update (self->ctx, buffer.len, buffer.buf);
                  Py_RETURN_NONE;
                ''')
        if param.get('digest', True):
            self.add_method(
                name='digest',
                args='METH_NOARGS',
                docs='Return the digest of the data passed to the update()'
                ' method so far. This is a bytes object of size digest_size'
                ' which may contain bytes in the whole range from 0 to 255.',
                body=f'''
                    uint8_t digest[{uname}_DIGEST_SIZE];
                    {lname}_digest (self->ctx, digest);
                    return PyBytes_FromStringAndSize ((const char *) digest,
                                                      {uname}_DIGEST_SIZE);
                ''')

            self.add_method(
                name='hexdigest',
                args='METH_NOARGS',
                docs='Like digest() except the digest is returned as a string'
                ' object of double length, containing only hexadecimal'
                ' digits. This may be used to exchange the value safely'
                ' in email or other non-binary environments.',
                body=f'''
                    uint8_t digest[{uname}_DIGEST_SIZE];
                    char hex[{uname}_DIGEST_SIZE * 2 + 1];
                    char *ptr = hex;
                    {lname}_digest (self->ctx, digest);
                    for (int i = 0; i < {uname}_DIGEST_SIZE; i++) {{
                      snprintf(ptr, 3, "%02X", digest[i]);
                      ptr += 2;
                    }}
                    return PyUnicode_FromString ((const char *) hex);
                ''')

        if param.get('shake'):
            self.add_method(
                name='shake',
                args='METH_VARARGS',
                docs=f'Performs final processing and produces a {uname} digest.'
                ' length can be of arbitrary size.',
                body=f'''
                    size_t length;
                    uint8_t *digest;
                    if (! PyArg_ParseTuple (args, "n", &length)) {{
                      return NULL;
                    }}
                    if ((digest = PyMem_Malloc(length)) == NULL) {{
                      return PyErr_NoMemory ();
                    }}
                    {lname}_shake (self->ctx, length, digest);
                    PyObject * bytes = PyBytes_FromStringAndSize (
                        (const char *) digest, length);
                    PyMem_Free(digest);
                    return bytes;
                ''')
            self.add_method(
                name='shake_output',
                args='METH_VARARGS',
                docs=f'Performs final processing and produces a {uname} digest.'
                ' length can be of arbitrary size.',
                body=f'''
                    size_t length;
                    uint8_t *digest;
                    if (! PyArg_ParseTuple (args, "n", &length)) {{
                      return NULL;
                    }}
                    if ((digest = PyMem_Malloc(length)) == NULL) {{
                      return PyErr_NoMemory ();
                    }}
                    {lname}_shake_output (self->ctx, length, digest);
                    PyObject * bytes = PyBytes_FromStringAndSize (
                        (const char *) digest, length);
                    PyMem_Free(digest);
                    return bytes;
                ''')

        self.add_method(
            name='copy',
            args='METH_NOARGS',
            docs='Return a copy (\\"clone\\") of the hash object. This can'
            ' be used to efficiently compute the digests of data sharing'
            ' a common initial substring',
            body=f'''
                PyObject * module = PyImport_ImportModule("nettle");
                PyObject * obj = PyObject_GetAttrString(module, "{name}");
                pynettle_{name} * copy= (pynettle_{name} *) \\
                   PyObject_CallObject (obj, NULL);
                memcpy(copy->ctx, self->ctx, sizeof (struct {lname}_ctx));
                return (PyObject *)copy;
            ''')
