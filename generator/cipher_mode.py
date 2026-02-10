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

from c_class import CClass
from params import CipherModeParam, CipherParam


class CipherFamilyError(Exception):
    """Trying to apply mode to cipher without family."""

class CipherMode(CClass):

    def __init__(self, param: CipherModeParam, ciphers: list[CipherParam]) -> None:
        CClass.__init__(self, name=param['name'], docs=param['docstring'])
        self.docs = param['docstring']

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
        if param.get('know_len'):
            self.add_member(
                name='authlen',
                decl='int authlen',
                init='self->authlen = 0;')
            self.add_member(
                name='msglen',
                decl='int msglen',
                init='self->msglen = 0;')
            self.add_member(
                name='taglen',
                decl='int taglen',
                init='self->taglen = 0;')

        if param.get('aead'):
            self.add_member(
                name=f'{lname}ctx',
                decl=f'struct {lname}_ctx *{lname}ctx',
                alloc=f'''
                    if ((self->{lname}ctx = PyMem_Malloc (sizeof (struct \\
                         {lname}_ctx))) == NULL)
                      {{
                        return PyErr_NoMemory ();
                      }}''',
                dealloc=f'''
                    PyMem_Free (self->{lname}ctx);
                    self->{lname}ctx = NULL;''')
            if param.get('mode_key'):
                self.add_member(
                    name=f'{lname}key',
                    decl=f'struct {lname}_key *{lname}key',
                    alloc=f'''
                        if ((self->{lname}key = PyMem_Malloc (sizeof (struct \\
                             {lname}_key))) == NULL)
                          {{
                            return PyErr_NoMemory ();
                          }}''',
                    dealloc=f'''
                        PyMem_Free (self->{lname}key);
                        self->{lname}key = NULL;''')
        else:
            self.add_member(
                name=param['iv'],
                decl='uint8_t * {}'.format(param['iv']),
                init='self->{} = NULL;'.format(param['iv']))

        if param.get('know_len'):
            self.args = 'cipher, {iv}, authlen, msglen, taglen' \
                .format(iv=param['iv'])
            self.add_to_init_body('''
                PyObject *obj = NULL;
                Py_buffer buffer;
                if (!PyArg_ParseTuple (args, "Oy*iii", &obj, &buffer, \\
                    &self->authlen, &self->msglen, &self->taglen))
                  {
                    return -1;
                  }
                if (obj != NULL)
                  {
            ''')
        else:
            self.args = 'cipher, {iv}'.format(iv=param['iv'])
            self.add_to_init_body('''
                PyObject *obj = NULL;
                Py_buffer buffer;
                if (!PyArg_ParseTuple (args, "Oy*", &obj, &buffer))
                  {
                    return -1;
                  }
                if (obj != NULL)
                  {
            ''')
        for c in ciphers:
            if 'family' not in c:
                raise CipherFamilyError(c['name'])
            self.add_to_init_body('''
                if (PyObject_TypeCheck (obj, &pynettle_{name}_Type))
                  {{
                    self->block_size = {FAMILY}_BLOCK_SIZE;
            '''.format(name=c['name'], FAMILY=c['family'].upper()))
            if not param.get('aead'):
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
                else'''.format(name=c['name']))
        self.add_to_init_body('''
                  {
                    PyErr_Format (PyExc_TypeError, "Expected cipher object");
                    return -1;
                  }
              }
        ''')
        encrypt = ''
        decrypt = ''
        if param.get('aead'):
            if param.get('update_cipher_param'):
                update_cipher = 'self->ctx, self->encrypt_func, '
            else:
                update_cipher = ''
            if param.get('digest_cipher_param'):
                digest_cipher = 'self->ctx, self->encrypt_func, '
            else:
                digest_cipher = ''
            if param.get('set_cipher_param'):
                set_cipher = 'self->ctx, self->encrypt_func, '
            else:
                set_cipher = ''
            if param.get('know_len'):
                know_len = ', self->authlen, self->msglen, self->taglen'
            else:
                know_len = ''
            if param.get('mode_key'):
                mode_key = f'self->{lname}key, '
                self.add_to_init_body(f'''
                    {lname}_set_key (self->{lname}key, self->ctx, \\
                                     self->encrypt_func);
                ''')
            else:
                mode_key = ''
            self.add_to_init_body('''
                {lname}_set_{iv} (self->{lname}ctx, {mode_key} \\
                                  {cipher}buffer.len, buffer.buf{know_len});
            '''.format(lname=lname, iv=param['iv'], mode_key=mode_key,
                       cipher=set_cipher, know_len=know_len))
            encrypt = f'''
                  {lname}_encrypt(self->{lname}ctx, {mode_key} \\
                                  self->ctx, \\
                  self->encrypt_func, buffer.len, dst, buffer.buf);
            '''
            decrypt = f'''
                  {lname}_decrypt(self->{lname}ctx, {mode_key} \\
                                  self->ctx, \\
                  self->decrypt_func, buffer.len, dst, buffer.buf);
            '''
            if param.get('know_len'):
                check_len = '''
                    if (buffer.len != self->authlen)
                      {
                        PyErr_Format (LenMismatch, "Authdata length (%d)" \\
                                      " not as specified earlier (%d)", \\
                                      buffer.len, self->authlen);
                        return NULL;
                      }
                '''
            else:
                check_len = ''
            self.add_method(
                name='update',
                args='METH_VARARGS',
                docs='Provides associated data to be authenticated. If used,'
                ' must be called before encrypt or decrypt. All but the last'
                ' call for each message must use a length that is a multiple'
                ' of the block size.',
                docargs='bytes',
                body=f'''
                    Py_buffer buffer;
                    if (!PyArg_ParseTuple (args, "y*", &buffer))
                      {{
                        return NULL;
                      }}
                    {check_len}
                    {lname}_update (self->{lname}ctx, \\
                                {mode_key}{update_cipher}buffer.len, buffer.buf);
                    Py_RETURN_NONE;
                ''')

            if param.get('know_len'):
                taglen = 'self->taglen'
            else:
                taglen = f'{name}_DIGEST_SIZE'
            self.add_method(
                name='digest',
                args='METH_NOARGS',
                docs='Extracts the message digest (also known as'
                ' \'authentication tag\'). This is the final operation when'
                ' processing a message. Note that unlike the nettle c'
                ' function, the state is not reset.',
                body=f'''
                    uint8_t digest[{name}_DIGEST_SIZE];
                    struct {lname}_ctx *ctx_copy;
                    if ((ctx_copy = PyMem_Malloc (sizeof \\
                          (struct {lname}_ctx))) == NULL) {{
                      return PyErr_NoMemory ();
                    }}
                    memcpy(ctx_copy, self->{lname}ctx, sizeof (struct \\
                           {lname}_ctx));
                    {lname}_digest (ctx_copy, \\
                        {mode_key}{digest_cipher}digest);
                    return PyBytes_FromStringAndSize ((const char *) digest, \\
                        {taglen});
                ''')

            self.add_method(
                name='hexdigest',
                args='METH_NOARGS',
                docs='Extracts the message digest (also known as'
                ' \'authentication tag\') as a hexadecimal string.'
                ' This is the final operation when processing a message.'
                ' Note that unlike the nettle c function, the state is not'
                ' reset.',
                body=f'''
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
                    {lname}_digest (ctx_copy, {mode_key}{digest_cipher}\\
                                    digest);
                    for (int i = 0; i < {taglen}; i++) {{
                      snprintf(ptr, 3, "%02X", digest[i]);
                      ptr += 2;
                    }}
                    return PyUnicode_FromString ((const char *) hex);
                    ''')
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
            if param.get('twofuncs'):
                en = 'en'
                de = 'de'
            else:
                en = ''
                de = ''
            encrypt = '''
                  {lname}_{en}crypt(self->ctx, self->encrypt_func, \\
                              self->block_size, self->{iv}, \\
                              buffer.len, dst, buffer.buf);
            '''.format(lname=lname, iv=param['iv'], en=en)
            decrypt = '''
                  {lname}_{de}crypt(self->ctx, self->decrypt_func, \\
                              self->block_size, self->{iv}, \\
                              buffer.len, dst, buffer.buf);
            '''.format(lname=lname, iv=param['iv'], de=de)

        if param.get('know_len'):
            check_len = '''
                if (buffer.len != self->msglen)
                  {
                    PyErr_Format (LenMismatch, "Message length (%d) not" \\
                                  " as specified earlier (%d)", \\
                                  buffer.len, self->msglen);
                    return NULL;
                  }
            '''
        else:
            check_len = ''
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
                Py_buffer buffer;
                if (!PyArg_ParseTuple (args, "y*", &buffer))
                    {
                      return NULL;
                    }
                  if ((dst = PyMem_Malloc (buffer.len)) == NULL)
                    {
                      return PyErr_NoMemory ();
                    }
            ''' + check_len + encrypt + '''
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
                Py_buffer buffer;
                if (!PyArg_ParseTuple (args, "y*", &buffer))
                    {
                      return NULL;
                    }
                  if ((dst = PyMem_Malloc (buffer.len)) == NULL)
                    {
                      return PyErr_NoMemory ();
                    }
            ''' + check_len + decrypt + '''
                  return PyBytes_FromStringAndSize ((const char *) dst,
                                                   buffer.len);
                ''')
