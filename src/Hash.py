#!/usr/bin/env python3

from CClass import CClass

class Hash(CClass):

    def __init__(self, name, docs):
         CClass.__init__(self, name, docs)
         
         self.add_member(
             name='ctx',
             decl='struct {}_ctx *ctx'.format(self.name),
             init='{}_init(self->ctx);'.format(self.name),
             alloc='if ((self->ctx = PyMem_Malloc(sizeof(struct {}_ctx)))'
             ' == NULL) {{\n    return PyErr_NoMemory();\n  }}'\
             .format(self.name),
             dealloc='PyMem_Free(self->ctx);\n  self->ctx = NULL;')
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
             body='''
  Py_buffer buffer;

  if (! PyArg_ParseTuple(args, "y*", &buffer)) {{
    return NULL;
  }}
  {name}_update(self->ctx, buffer.len, buffer.buf);
  Py_RETURN_NONE;
'''.format(name=name))
         self.add_method(
             name='digest',
             args='METH_NOARGS',
             docs='Performs final processing and extracts the message digest',
             body='''
  uint8_t digest[{NAME}_DIGEST_SIZE];

  {name}_digest(self->ctx, {NAME}_DIGEST_SIZE, digest);
  return PyBytes_FromStringAndSize((const char *)digest, {NAME}_DIGEST_SIZE);
'''.format(name=name, NAME=name.upper()))
