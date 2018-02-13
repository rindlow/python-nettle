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
from textwrap import dedent


class Hash(CClass):

    def __init__(self, name, docs):
        CClass.__init__(self, name, docs)

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
            body=dedent('''
                #if PY_MAJOR_VERSION >= 3
                  Py_buffer buffer;

                  if (! PyArg_ParseTuple (args, "y*", &buffer)) {{
                #else
                  nettle_py2buf buffer;
                  if (! PyArg_ParseTuple (args, "t#",
                                          &buffer.buf, &buffer.len)) {{
                #endif
                    return NULL;
                  }}
                  {name}_update (self->ctx, buffer.len, buffer.buf);
                  Py_RETURN_NONE;
                ''').format(name=name))
        self.add_method(
            name='digest',
            args='METH_NOARGS',
            docs='Performs final processing and extracts the message digest',
            body='''
  uint8_t digest[{NAME}_DIGEST_SIZE];

  {name}_digest (self->ctx, {NAME}_DIGEST_SIZE, digest);
  return PyBytes_FromStringAndSize ((const char *) digest, {NAME}_DIGEST_SIZE);
'''.format(name=name, NAME=name.upper()))
