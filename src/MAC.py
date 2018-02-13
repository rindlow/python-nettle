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

from CClass import CClass
from textwrap import dedent


class MAC(CClass):

    def __init__(self, name, docs):
        CClass.__init__(self, name, docs)

        self.add_member(
            name='is_initialized',
            decl='int is_initialized',
            init='self->is_initialized = 0;')
        self.add_member(
            name='ctx',
            decl='struct {}_ctx *ctx'.format(self.name),
            alloc='if ((self->ctx = PyMem_Malloc (sizeof (struct {}_ctx)))'
            ' == NULL)\n    {{\n      return PyErr_NoMemory ();\n    }}'
            .format(self.name),
            dealloc='PyMem_Free (self->ctx);\n  self->ctx = NULL;')

        if name[:4] == 'hmac':
            digestsize = '{}_DIGEST_SIZE'.format(name[5:].upper())
            blocksize = '{}_BLOCK_SIZE'.format(name[5:].upper())
            keylen = 'key.len, '
            self.add_bufferparse_to_init(['key', 'nonce'])
            self.add_to_init_body('  if (key.buf != NULL)\n    {{\n'
                                  '      {name}_set_key (self->ctx,'
                                  ' key.len, key.buf);\n'
                                  '      self->is_initialized = 1;\n'
                                  '    }}\n'
                                  .format(name=name))
        else:
            digestsize = '{}_DIGEST_SIZE'.format(name.upper())
            keylen = ''
            if name[:4] == 'umac':
                blocksize = 'UMAC_BLOCK_SIZE'
            else:
                blocksize = 'AES_BLOCK_SIZE'
            self.add_bufferparse_to_init(['key', 'nonce'])
            self.add_to_init_body(dedent('''
                if (key.buf != NULL)
                  {{
                    {name}_set_key (self->ctx, key.buf);
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
                    {name}_set_nonce (self->ctx, nonce.len, nonce.buf);
                  }}
            ''').format(name=name))
            self.add_method(
                name='set_nonce',
                args='METH_VARARGS',
                docs='Initializes the MAC with the nonce',
                body=dedent('''
                      if (!self->is_initialized)
                        {{
                          PyErr_Format (NotInitializedError,
                                     "Cipher not initialized. Set key first!");
                          return NULL;
                        }}
                    #if PY_MAJOR_VERSION >= 3
                      Py_buffer nonce;

                      if (! PyArg_ParseTuple (args, "y*", &nonce))
                    #else
                      nettle_py2buf nonce;
                      if (! PyArg_ParseTuple (args, "t#",
                                             &nonce.buf, &nonce.len))
                    #endif
                        {{
                          return NULL;
                        }}
                      {name}_set_nonce (self->ctx, nonce.len, nonce.buf);
                      Py_RETURN_NONE;
                    ''').format(name=name))

        self.add_member(
            name='digest_size',
            decl='int digest_size',
            init='self->digest_size = {};'.format(digestsize),
            docs='The size of a {} digest'.format(name.upper()),
            flags='READONLY',
            type='T_INT',
            public=True)
        self.add_member(
            name='block_size',
            decl='int block_size',
            init='self->block_size = {};'.format(blocksize),
            docs='The internal block size of {}'.format(name.upper()),
            flags='READONLY',
            type='T_INT',
            public=True)
        self.add_method(
            name='set_key',
            args='METH_VARARGS',
            docs='Initializes the MAC with the key',
            body=dedent('''
                #if PY_MAJOR_VERSION >= 3
                  Py_buffer key;

                  if (! PyArg_ParseTuple (args, "y*", &key))
                #else
                  nettle_py2buf key;
                  if (! PyArg_ParseTuple (args, "t#",
                                         &key.buf, &key.len))
                #endif
                    {{
                      return NULL;
                    }}
                  {name}_set_key (self->ctx, {keylen}key.buf);
                  self->is_initialized = 1;
                  Py_RETURN_NONE;
                ''').format(name=name, keylen=keylen))
        self.add_method(
            name='update',
            args='METH_VARARGS',
            docs='Process some more data',
            body=dedent('''
                  if (!self->is_initialized)
                    {{
                      PyErr_Format (NotInitializedError,
                                    "Cipher not initialized. Set key first!");
                      return NULL;
                    }}
                #if PY_MAJOR_VERSION >= 3
                  Py_buffer buffer;

                  if (! PyArg_ParseTuple (args, "y*", &buffer))
                #else
                  nettle_py2buf buffer;
                  if (! PyArg_ParseTuple (args, "t#",
                                         &buffer.buf, &buffer.len))
                #endif
                    {{
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
  uint8_t digest[{DIGESTSIZE}];

  if (!self->is_initialized)
    {{
      PyErr_Format (NotInitializedError,
                    "Cipher not initialized. Set key first!");
      return NULL;
    }}
  {name}_digest (self->ctx, {DIGESTSIZE}, digest);
  return PyBytes_FromStringAndSize ((const char *) digest, {DIGESTSIZE});
'''.format(name=name, DIGESTSIZE=digestsize))

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
              if (! PyArg_ParseTupleAndKeywords (args, kwds, "{py3fmt}", \\
                                                 kwlist,
                                                 {py3pointers}))
            #else
              if (! PyArg_ParseTupleAndKeywords (args, kwds, "{py2fmt}", \\
                                                 kwlist,
                                                 {py2pointers}))
            #endif
                {{
                  return -1;
                }}
            ''').format(kwlist='{{"{}", NULL}}'.format('", "'.join(buffers)),
                        vars=', '.join(buffers),
                        nullify='\n  '.join(['{b}.buf = NULL; {b}.len = 0;'
                                             .format(b=b) for b in buffers]),
                        py2fmt='|' + 't#' * len(buffers),
                        py3fmt='|' + 'z*' * len(buffers),
                        py2pointers=(',\n' + ' ' * 37).join(
                            ['&{b}.buf, &{b}.len'.format(b=b)
                             for b in buffers]),
                        py3pointers=', '.join(['&{}'.format(b)
                                               for b in buffers])))
