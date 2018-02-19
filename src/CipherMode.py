# -*- coding: utf-8 -*-
#
# CipherMode.py
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


class CipherMode(CClass):

    def __init__(self, name, docs, ciphers):
        CClass.__init__(self, name=name, docs=docs)

        self.add_member(
            name='cipher',
            decl='PyObject * cipher',
            init='self->cipher = NULL;')
        self.add_member(
            name='ctx',
            decl='void * ctx',
            init='self->ctx = NULL;')
        self.add_member(
            name='block_size',
            decl='int block_size',
            init='self->block_size = 0;')
        self.add_member(
            name='cipher_is_initialized_p',
            decl='int *cipher_is_initialized_p',
            init='self->cipher_is_initialized_p = NULL;')
        self.add_member(
            name='encrypt_func',
            decl='nettle_cipher_func *encrypt_func',
            init='self->encrypt_func = NULL;')
        self.add_member(
            name='decrypt_func',
            decl='nettle_cipher_func *decrypt_func',
            init='self->decrypt_func = NULL;')
        if name == 'CBC':
            self.add_member(
                name='iv',
                decl='uint8_t *iv',
                init='self->iv = NULL;')
        if name == 'CTR':
            self.add_member(
                name='ctr',
                decl='uint8_t *ctr',
                init='self->ctr = NULL;')
        if name == 'GCM':
            self.add_member(
                name='gcmctx',
                decl='struct gcm_ctx *gcmctx',
                alloc='''
                if ((self->gcmctx = PyMem_Malloc (sizeof (struct \\
                     gcm_ctx))) == NULL)
                  {
                    return PyErr_NoMemory ();
                  }''',
                dealloc='PyMem_Free (self->gcmctx);\nself->gcmctx = NULL;')
            self.add_member(
                name='gcmkey',
                decl='struct gcm_key *gcmkey',
                alloc='''
                    if ((self->gcmkey = PyMem_Malloc (sizeof (struct \\
                         gcm_key))) == NULL)
                      {
                        return PyErr_NoMemory ();
                      }''',
                dealloc='PyMem_Free (self->gcmkey);\nself->gcmkey = NULL;')

        self.add_to_init_body(dedent('''
            PyObject *obj = NULL;
            #if PY_MAJOR_VERSION >= 3
            Py_buffer buffer;
            if (!PyArg_ParseTuple (args, "Oy*", &obj, &buffer))
            #else
            nettle_py2buf buffer;
            if (!PyArg_ParseTuple (args, "Ot#", &obj, &buffer.buf, \\
                &buffer.len))
            #endif
              {
                return -1;
              }
            if (obj != NULL)
              {
        '''))
        for c in ciphers:
            self.add_to_init_body(dedent('''
                if (PyObject_TypeCheck (obj, &pynettle_{name}_Type))
                  {{
                    self->block_size = {FAMILY}_BLOCK_SIZE;
            ''').format(name=c['name'], FAMILY=c['family'].upper()))
            if name == 'CBC':
                self.add_to_init_body('''   if ((self->iv = malloc({FAMILY}_BLOCK_SIZE)) == NULL)
                      {{
                        PyErr_NoMemory();
                        return -1;
                      }}'''.format(FAMILY=c['family'].upper()))
            elif name == 'CTR':
                self.add_to_init_body('''   if ((self->ctr = malloc({FAMILY}_BLOCK_SIZE)) == NULL)
                      {{
                        PyErr_NoMemory();
                        return -1;
                      }}'''.format(FAMILY=c['family'].upper()))

            self.add_to_init_body('''
                    self->ctx = ((pynettle_{name} *) obj)->ctx;
                    self->encrypt_func = ((pynettle_{name} *)obj)\\
                        ->encrypt_func;
                    self->decrypt_func = ((pynettle_{name} *)obj)\\
                        ->decrypt_func;
                    self->cipher_is_initialized_p = &((pynettle_{name} *)obj)\\
                        ->is_initialized;
                    self->cipher = obj;
                    Py_INCREF (self->cipher);
                  }}
                else'''.format(name=c['name'], FAMILY=c['family'].upper()))
        self.add_to_init_body('''
                  {
                    PyErr_Format (PyExc_TypeError, "Expected cipher object");
                    return -1;
                  }
              }
        ''')
        if name == 'CBC':
            self.add_to_init_body('''
                if (buffer.len != self->block_size)
                  {
                    PyErr_Format(KeyLenError, "IV is not a block long");
                  }
                if (buffer.buf != NULL)
                  {
                    memcpy (self->iv, buffer.buf, buffer.len);
                  }
            ''')
            encrypt = '''
                  cbc_encrypt(self->ctx, self->encrypt_func, \\
                              self->block_size, self->iv, \\
                              buffer.len, dst, buffer.buf);
            '''
            decrypt = '''
                  cbc_decrypt(self->ctx, self->decrypt_func, \\
                              self->block_size, self->iv, \\
                              buffer.len, dst, buffer.buf);
            '''
        elif name == 'CTR':
            self.add_to_init_body('''
                if (buffer.len != self->block_size)
                  {
                    PyErr_Format(KeyLenError, "CTR is not a block long");
                  }
                if (buffer.buf != NULL)
                  {
                   memcpy (self->ctr, buffer.buf, buffer.len);
                  }
            ''')
            encrypt = '''
                  ctr_crypt(self->ctx, self->encrypt_func, \\
                              self->block_size, self->ctr, \\
                              buffer.len, dst, buffer.buf);
            '''
            decrypt = '''
                  ctr_crypt(self->ctx, self->decrypt_func, \\
                              self->block_size, self->ctr, \\
                              buffer.len, dst, buffer.buf);
            '''
        elif name == 'GCM':
            self.add_to_init_body('''
              gcm_set_iv (self->gcmctx, self->gcmkey, buffer.len, buffer.buf);
              gcm_set_key (self->gcmkey, self->ctx, self->encrypt_func);
            ''')
            encrypt = '''
                  gcm_encrypt(self->gcmctx, self->gcmkey, self->ctx, \\
                  self->encrypt_func, buffer.len, dst, buffer.buf);
            '''
            decrypt = '''
                  gcm_decrypt(self->gcmctx, self->gcmkey, self->ctx, \\
                  self->decrypt_func, buffer.len, dst, buffer.buf);
            '''
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
                    if (!PyArg_ParseTuple (args, "y*", &buffer))
                    #else
                    nettle_py2buf buffer;
                    if (!PyArg_ParseTuple (args, "t#", \\
                        &buffer.buf, &buffer.len))
                    #endif
                      {
                        return NULL;
                      }
                    gcm_update (self->gcmctx, self->gcmkey, buffer.len,
                                buffer.buf);
                    Py_RETURN_NONE;
                '''))

            self.add_method(
                name='digest',
                args='METH_NOARGS',
                docs='Extracts the message digest (also known as'
                ' \'authentication tag\'). This is the final operation when'
                ' processing a message. It’s strongly recommended that'
                ' length is GCM_DIGEST_SIZE, but if you provide a smaller'
                ' value, only the first length octets'
                ' of the digest are written.',
                body='''
                    uint8_t digest[GCM_DIGEST_SIZE];
                    gcm_digest (self->gcmctx, self->gcmkey, self->ctx, \\
                        self->encrypt_func, GCM_DIGEST_SIZE, digest);
                    return PyBytes_FromStringAndSize ((const char *) digest, \\
                        GCM_DIGEST_SIZE);
                ''')

        self.add_method(
            name='encrypt',
            args='METH_VARARGS',
            docs='Encrypts data, the length of which must be an'
            ' integral multiple of the block size',
            body='''
                if (! *self->cipher_is_initialized_p)
                  {
                    PyErr_Format (NotInitializedError,
                                    "Cipher not initialized. Set key first!");
                    return NULL;
                  }
                uint8_t *dst;
                #if PY_MAJOR_VERSION >= 3
                Py_buffer buffer;
                if (!PyArg_ParseTuple (args, "y*", &buffer))
                #else
                nettle_py2buf buffer;
                if (!PyArg_ParseTuple (args, "t#",
                                       &buffer.buf, &buffer.len))
                #endif
                    {
                      return NULL;
                    }
                  if ((dst = PyMem_Malloc (buffer.len)) == NULL)
                    {
                      return PyErr_NoMemory ();
                    }
            ''' + encrypt + '''
                  return PyBytes_FromStringAndSize ((const char *) dst,
                                                   buffer.len);
            ''')
        self.add_method(
            name='decrypt',
            args='METH_VARARGS',
            docs='Decrypts data, the length of which must be an'
            ' integral multiple of the block size',
            body='''
                if (! *self->cipher_is_initialized_p)
                  {
                    PyErr_Format (NotInitializedError,
                                    "Cipher not initialized. Set key first!");
                    return NULL;
                  }
                uint8_t *dst;
                #if PY_MAJOR_VERSION >= 3
                Py_buffer buffer;
                if (!PyArg_ParseTuple (args, "y*", &buffer))
                #else
                nettle_py2buf buffer;
                if (!PyArg_ParseTuple (args, "t#",
                                       &buffer.buf, &buffer.len))
                #endif
                    {
                      return NULL;
                    }
                  if ((dst = PyMem_Malloc (buffer.len)) == NULL)
                    {
                      return PyErr_NoMemory ();
                    }
            ''' + decrypt + '''
                  return PyBytes_FromStringAndSize ((const char *) dst,
                                                   buffer.len);
                ''')
