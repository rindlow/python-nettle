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

from CClass import CClass


class Hash(CClass):

    def __init__(self, name, digest, shake, docs):
        CClass.__init__(self, name, docs, args='[msg]')

        self.add_to_init_body('''
                  Py_buffer buffer;
                  buffer.buf = NULL;
                  if (! PyArg_ParseTuple (args, "|y*", &buffer)) {{
                    return -1;
                  }}
                  if (buffer.buf != NULL) {{
                    {name}_update (self->ctx, buffer.len, buffer.buf);
                  }}
        '''.format(name=name))

        self.add_member(
            name='ctx',
            decl='struct {}_ctx *ctx'.format(self.name),
            init='{}_init (self->ctx);'.format(self.name),
            alloc='if ((self->ctx = PyMem_Malloc (sizeof (struct {}_ctx)))'
            ' == NULL) {{\n    return PyErr_NoMemory ();\n  }}'
            .format(self.name),
            dealloc='PyMem_Free (self->ctx);\n  self->ctx = NULL;')
        self.add_member(
            name='digest_size',
            decl='int digest_size',
            init='self->digest_size = {}_DIGEST_SIZE;'.format(name.upper()),
            docs='The size of a {} digest'.format(name.upper()),
            flags='READONLY',
            type='T_INT',
            public=True)
        self.add_member(
            name='block_size',
            decl='int block_size',
            init='self->block_size = {}_BLOCK_SIZE;'.format(name.upper()),
            docs='The internal block size of {}'.format(name.upper()),
            flags='READONLY',
            type='T_INT',
            public=True)
        self.add_method(
            name='update',
            args='METH_VARARGS',
            docs='Hash some more data',
            docargs='msg',
            body='''
                  Py_buffer buffer;

                  if (! PyArg_ParseTuple (args, "y*", &buffer)) {{
                    return NULL;
                  }}
                  {name}_update (self->ctx, buffer.len, buffer.buf);
                  Py_RETURN_NONE;
                '''.format(name=name))
        if digest:
            self.add_method(
                name='digest',
                args='METH_NOARGS',
                docs='Return the digest of the data passed to the update()'
                ' method so far. This is a bytes object of size digest_size'
                ' which may contain bytes in the whole range from 0 to 255.',
                body='''
                    uint8_t digest[{NAME}_DIGEST_SIZE];
                    {name}_digest (self->ctx, {NAME}_DIGEST_SIZE, digest);
                    return PyBytes_FromStringAndSize ((const char *) digest,
                                                      {NAME}_DIGEST_SIZE);
                '''.format(name=name, NAME=name.upper()))

            self.add_method(
                name='hexdigest',
                args='METH_NOARGS',
                docs='Like digest() except the digest is returned as a string'
                ' object of double length, containing only hexadecimal'
                ' digits. This may be used to exchange the value safely'
                ' in email or other non-binary environments.',
                body='''
                    uint8_t digest[{NAME}_DIGEST_SIZE];
                    char hex[{NAME}_DIGEST_SIZE * 2 + 1];
                    char *ptr = hex;
                    {name}_digest (self->ctx, {NAME}_DIGEST_SIZE, digest);
                    for (int i = 0; i < {NAME}_DIGEST_SIZE; i++) {{
                      snprintf(ptr, 3, "%02X", digest[i]);
                      ptr += 2;
                    }}
                    return PyUnicode_FromString ((const char *) hex);
                '''.format(name=name, NAME=name.upper()))

        if shake:
            self.add_method(
                name='shake',
                args='METH_VARARGS',
                docs='Performs final processing and produces a {NAME} digest.'
                ' length can be of arbitrary size.'.format(NAME=name.upper()),
                body='''
                    size_t length;
                    uint8_t *digest;
                    if (! PyArg_ParseTuple (args, "n", &length)) {{
                      return NULL;
                    }}
                    if ((digest = PyMem_Malloc(length)) == NULL) {{
                      return PyErr_NoMemory ();
                    }}
                    {name}_shake (self->ctx, length, digest);
                    PyObject * bytes = PyBytes_FromStringAndSize (
                        (const char *) digest, length);
                    PyMem_Free(digest);
                    return bytes;
                '''.format(name=name))
            self.add_method(
                name='shake_output',
                args='METH_VARARGS',
                docs='Performs final processing and produces a {NAME} digest.'
                ' length can be of arbitrary size.'.format(NAME=name.upper()),
                body='''
                    size_t length;
                    uint8_t *digest;
                    if (! PyArg_ParseTuple (args, "n", &length)) {{
                      return NULL;
                    }}
                    if ((digest = PyMem_Malloc(length)) == NULL) {{
                      return PyErr_NoMemory ();
                    }}
                    {name}_shake_output (self->ctx, length, digest);
                    PyObject * bytes = PyBytes_FromStringAndSize (
                        (const char *) digest, length);
                    PyMem_Free(digest);
                    return bytes;
                '''.format(name=name))

        self.add_method(
            name='copy',
            args='METH_NOARGS',
            docs='Return a copy (\\"clone\\") of the hash object. This can'
            ' be used to efficiently compute the digests of data sharing'
            ' a common initial substring',
            body='''
                PyObject * module = PyImport_ImportModule("nettle");
                PyObject * obj = PyObject_GetAttrString(module, "{name}");
                pynettle_{name} * copy= (pynettle_{name} *) \\
                   PyObject_CallObject (obj, NULL);
                memcpy(copy->ctx, self->ctx, sizeof (struct {name}_ctx));
                return (PyObject *)copy;
            '''.format(name=name))
