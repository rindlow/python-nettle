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


class CipherMode(CClass):

    def __init__(self, param, ciphers):
        CClass.__init__(self, name=param['name'], docs=param['docs'])

        name = param['name']
        lname = name.lower()
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

        if param['aead']:
            self.add_member(
                name='{lname}ctx'.format(lname=lname),
                decl='struct {lname}_ctx *{lname}ctx'.format(lname=lname),
                alloc='''
                    if ((self->{lname}ctx = PyMem_Malloc (sizeof (struct \\
                         {lname}_ctx))) == NULL)
                      {{
                        return PyErr_NoMemory ();
                      }}'''.format(lname=lname),
                dealloc='''
                    PyMem_Free (self->{lname}ctx);
                    self->{lname}ctx = NULL;'''.format(lname=lname))
            self.add_member(
                name='{lname}key',
                decl='struct {lname}_key *{lname}key'.format(lname=lname),
                alloc='''
                    if ((self->{lname}key = PyMem_Malloc (sizeof (struct \\
                         {lname}_key))) == NULL)
                      {{
                        return PyErr_NoMemory ();
                      }}'''.format(lname=lname),
                dealloc='''
                    PyMem_Free (self->{lname}key);
                    self->{lname}key = NULL;'''.format(lname=lname))
            self.args = 'cipher, initial_{iv}'.format(iv=param['iv'])
        else:
            self.add_member(
                name=param['iv'],
                decl='uint8_t * {}'.format(param['iv']),
                init='self->{} = NULL;'.format(param['iv']))
            self.args = 'cipher, initial_{}'.format(param['iv'])


        self.add_to_init_body('''
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
        ''')
        for c in ciphers:
            self.add_to_init_body('''
                if (PyObject_TypeCheck (obj, &pynettle_{name}_Type))
                  {{
                    self->block_size = {FAMILY}_BLOCK_SIZE;
            '''.format(name=c['name'], FAMILY=c['family'].upper()))
            if not param['aead']:
                self.add_to_init_body('''
                    if ((self->{iv} = malloc({FAMILY}_BLOCK_SIZE)) == NULL)
                      {{
                        PyErr_NoMemory();
                        return -1;
                      }}'''.format(iv=param['iv'], FAMILY=c['family'].upper()))

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
        encrypt = ''
        decrypt = ''
        if param['aead']:
            if param['cipher_param']:
                cipher = 'self->ctx, self->encrypt_func, '
            else:
                cipher = ''
            self.add_to_init_body('''
              {lname}_set_key (self->{lname}key, self->ctx, \\
                               self->encrypt_func);
              {lname}_set_{iv} (self->{lname}ctx, self->{lname}key, \\
                              {cipher}buffer.len, buffer.buf);
            '''.format(lname=lname, iv=param['iv'], cipher=cipher))
            encrypt = '''
                  {lname}_encrypt(self->{lname}ctx, self->{lname}key, \\
                                  self->ctx, \\
                  self->encrypt_func, buffer.len, dst, buffer.buf);
            '''.format(lname=lname)
            decrypt = '''
                  {lname}_decrypt(self->{lname}ctx, self->{lname}key, \\
                                  self->ctx, \\
                  self->decrypt_func, buffer.len, dst, buffer.buf);
            '''.format(lname=lname)
            self.add_method(
                name='update',
                args='METH_VARARGS',
                docs='Provides associated data to be authenticated. If used,'
                ' must be called before encrypt or decrypt. All but the last'
                ' call for each message must use a length that is a multiple'
                ' of the block size.',
                docargs='bytes',
                body='''
                    #if PY_MAJOR_VERSION >= 3
                    Py_buffer buffer;
                    if (!PyArg_ParseTuple (args, "y*", &buffer))
                    #else
                    nettle_py2buf buffer;
                    if (!PyArg_ParseTuple (args, "t#", \\
                        &buffer.buf, &buffer.len))
                    #endif
                      {{
                        return NULL;
                      }}
                    {lname}_update (self->{lname}ctx, self->{lname}key, \\
                                {cipher}buffer.len, buffer.buf);
                    Py_RETURN_NONE;
                '''.format(lname=lname, cipher=cipher))

            self.add_method(
                name='digest',
                args='METH_NOARGS',
                docs='Extracts the message digest (also known as'
                ' \'authentication tag\'). This is the final operation when'
                ' processing a message. Note that unlike the nettle c'
                ' function, the state is not reset.',
                body='''
                    uint8_t digest[{name}_DIGEST_SIZE];
                    struct {lname}_ctx *ctx_copy;
                    if ((ctx_copy = PyMem_Malloc (sizeof \\
                          (struct {lname}_ctx))) == NULL) {{
                      return PyErr_NoMemory ();
                    }}
                    memcpy(ctx_copy, self->{lname}ctx, sizeof (struct \\
                           {lname}_ctx));
                    {lname}_digest (ctx_copy, self->{lname}key, self->ctx, \\
                        self->encrypt_func, {name}_DIGEST_SIZE, digest);
                    return PyBytes_FromStringAndSize ((const char *) digest, \\
                        {name}_DIGEST_SIZE);
                '''.format(name=name, lname=lname))

            self.add_method(
                name='hexdigest',
                args='METH_NOARGS',
                docs='Extracts the message digest (also known as'
                ' \'authentication tag\') as a hexadecimal string.'
                ' This is the final operation when processing a message.'
                ' Note that unlike the nettle c function, the state is not'
                ' reset.',
                body='''
                    uint8_t digest[{name}_DIGEST_SIZE];
                    char hex[{name}_DIGEST_SIZE * 2 + 1];
                    char *ptr = hex;
                    struct {lname}_ctx *ctx_copy;
                    if ((ctx_copy = PyMem_Malloc (sizeof \\
                          (struct {lname}_ctx))) == NULL) {{
                      return PyErr_NoMemory ();
                    }}
                    memcpy(ctx_copy, self->{lname}ctx, sizeof \\
                           (struct {lname}_ctx));
                    {lname}_digest (ctx_copy, self->{lname}key, self->ctx, \\
                        self->encrypt_func, {name}_DIGEST_SIZE, digest);
                    for (int i = 0; i < {name}_DIGEST_SIZE; i++) {{
                      snprintf(ptr, 3, "%02X", digest[i]);
                      ptr += 2;
                    }}
                  #if PY_MAJOR_VERSION >= 3
                    return PyUnicode_FromString ((const char *) hex);
                  #else
                    return PyString_FromString ((const char *) hex);
                  #endif
                    '''.format(name=name, lname=lname))
        else:
            self.add_to_init_body('''
                if (buffer.len != self->block_size)
                  {{
                    PyErr_Format(KeyLenError, "{IV} is not a block long");
                  }}
                if (buffer.buf != NULL)
                  {{
                    memcpy (self->{iv}, buffer.buf, buffer.len);
                  }}
            '''.format(iv=param['iv'], IV=param['iv'].upper()))
            if param['twofuncs']:
                en = 'en'
                de = 'de'
            else:
                en = ''
                de = ''
            encrypt = '''
                  {lname}_{en}crypt(self->ctx, self->encrypt_func, \\
                              self->block_size, self->{iv}, \\
                              buffer.len, dst, buffer.buf);
            '''.format(lname=lname, iv=param['iv'], en=en, de=de)
            decrypt = '''
                  {lname}_{de}crypt(self->ctx, self->decrypt_func, \\
                              self->block_size, self->{iv}, \\
                              buffer.len, dst, buffer.buf);
            '''.format(lname=lname, iv=param['iv'], en=en, de=de)

        self.add_method(
            name='encrypt',
            args='METH_VARARGS',
            docs='Encrypts data, the length of which must be an'
            ' integral multiple of the block size',
            docargs='msg',
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
            docargs='msg',
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
