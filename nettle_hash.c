#include <Python.h>
#include "structmember.h"
#include <nettle/sha1.h>
#include <nettle/sha2.h>

typedef struct {
  PyObject_HEAD
  struct sha256_ctx *ctx;
  int digest_size;
  int block_size;
} pynettle_sha256;


static PyObject *
pynettle_sha256_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  pynettle_sha256 *self;

  self = (pynettle_sha256 *)type->tp_alloc(type, 0);
  return (PyObject *)self;
}

static int
pynettle_sha256_init(pynettle_sha256 *self, PyObject *args, PyObject *kwds)
{
  if ((self->ctx = PyMem_Malloc(sizeof(struct sha256_ctx))) == NULL) {
    PyErr_NoMemory();
    return -1;
  }
  sha256_init(self->ctx);
  self->digest_size = SHA256_DIGEST_SIZE;
  self->block_size = SHA256_BLOCK_SIZE;
  return 0;
}

void
pynettle_sha256_dealloc(pynettle_sha256 *self)
{
  PyMem_Free(self->ctx);
  self->ctx = NULL;
}

void
pynettle_sha256_update(pynettle_sha256 *self, PyObject *args)
{
  Py_buffer buffer;

  if (! PyArg_ParseTuple(args, "y*", &buffer)) {
    return;
  }
  sha256_update(self->ctx, buffer.len, buffer.buf);
}

static PyObject *
pynettle_sha256_digest(pynettle_sha256 *self)
{
  uint8_t digest[SHA256_DIGEST_SIZE];

  sha256_digest(self->ctx, SHA256_DIGEST_SIZE, digest);
  return PyBytes_FromStringAndSize((const char *)digest, SHA256_DIGEST_SIZE);
}

static PyMethodDef pynettle_sha256_methods[] = {
  {"update", (PyCFunction)pynettle_sha256_update, METH_VARARGS,
   "Hash some more data"},
  {"digest", (PyCFunction)pynettle_sha256_digest, METH_NOARGS,
    "Performs final processing and extracts the message digest"},
  {NULL}
};

static PyMemberDef pynettle_sha256_members[] = {
  {"block_size", T_INT, offsetof(pynettle_sha256, block_size),
    READONLY, "The internal block size of SHA256"},
  {"digest_size", T_INT, offsetof(pynettle_sha256, digest_size),
    READONLY, "The size of a SHA256 digest"},
  {NULL}
};

static PyTypeObject pynettle_sha256_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "nettle.hash.sha256",             /* tp_name */
    sizeof(pynettle_sha256),     /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)pynettle_sha256_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "SHA256 is a member of the SHA2 family. It outputs hash values of 256 bits, or 32 octets.",	       /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    pynettle_sha256_methods,     /* tp_methods */
    pynettle_sha256_members,     /* tp_members */
    0,			       /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)pynettle_sha256_init, /* tp_init */
    0,                         /* tp_alloc */
    pynettle_sha256_new,	       /* tp_new */
};

typedef struct {
  PyObject_HEAD
  struct sha1_ctx *ctx;
  int digest_size;
  int block_size;
} pynettle_sha1;


static PyObject *
pynettle_sha1_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  pynettle_sha1 *self;

  self = (pynettle_sha1 *)type->tp_alloc(type, 0);
  return (PyObject *)self;
}

static int
pynettle_sha1_init(pynettle_sha1 *self, PyObject *args, PyObject *kwds)
{
  if ((self->ctx = PyMem_Malloc(sizeof(struct sha1_ctx))) == NULL) {
    PyErr_NoMemory();
    return -1;
  }
  sha1_init(self->ctx);
  self->digest_size = SHA1_DIGEST_SIZE;
  self->block_size = SHA1_BLOCK_SIZE;
  return 0;
}

void
pynettle_sha1_dealloc(pynettle_sha1 *self)
{
  PyMem_Free(self->ctx);
  self->ctx = NULL;
}

void
pynettle_sha1_update(pynettle_sha1 *self, PyObject *args)
{
  Py_buffer buffer;

  if (! PyArg_ParseTuple(args, "y*", &buffer)) {
    return;
  }
  sha1_update(self->ctx, buffer.len, buffer.buf);
}

static PyObject *
pynettle_sha1_digest(pynettle_sha1 *self)
{
  uint8_t digest[SHA1_DIGEST_SIZE];

  sha1_digest(self->ctx, SHA1_DIGEST_SIZE, digest);
  return PyBytes_FromStringAndSize((const char *)digest, SHA1_DIGEST_SIZE);
}

static PyMethodDef pynettle_sha1_methods[] = {
  {"update", (PyCFunction)pynettle_sha1_update, METH_VARARGS,
   "Hash some more data"},
  {"digest", (PyCFunction)pynettle_sha1_digest, METH_NOARGS,
    "Performs final processing and extracts the message digest"},
  {NULL}
};

static PyMemberDef pynettle_sha1_members[] = {
  {"block_size", T_INT, offsetof(pynettle_sha1, block_size),
    READONLY, "The internal block size of SHA1"},
  {"digest_size", T_INT, offsetof(pynettle_sha1, digest_size),
    READONLY, "The size of a SHA1 digest"},
  {NULL}
};

static PyTypeObject pynettle_sha1_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "nettle.hash.sha1",             /* tp_name */
    sizeof(pynettle_sha1),     /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)pynettle_sha1_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "SHA1 is a hash function specified by NIST (The U.S. National Institute for Standards and Technology).",	       /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    pynettle_sha1_methods,     /* tp_methods */
    pynettle_sha1_members,     /* tp_members */
    0,			       /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)pynettle_sha1_init, /* tp_init */
    0,                         /* tp_alloc */
    pynettle_sha1_new,	       /* tp_new */
};

typedef struct {
  PyObject_HEAD
  struct sha224_ctx *ctx;
  int digest_size;
  int block_size;
} pynettle_sha224;


static PyObject *
pynettle_sha224_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  pynettle_sha224 *self;

  self = (pynettle_sha224 *)type->tp_alloc(type, 0);
  return (PyObject *)self;
}

static int
pynettle_sha224_init(pynettle_sha224 *self, PyObject *args, PyObject *kwds)
{
  if ((self->ctx = PyMem_Malloc(sizeof(struct sha224_ctx))) == NULL) {
    PyErr_NoMemory();
    return -1;
  }
  sha224_init(self->ctx);
  self->digest_size = SHA224_DIGEST_SIZE;
  self->block_size = SHA224_BLOCK_SIZE;
  return 0;
}

void
pynettle_sha224_dealloc(pynettle_sha224 *self)
{
  PyMem_Free(self->ctx);
  self->ctx = NULL;
}

void
pynettle_sha224_update(pynettle_sha224 *self, PyObject *args)
{
  Py_buffer buffer;

  if (! PyArg_ParseTuple(args, "y*", &buffer)) {
    return;
  }
  sha224_update(self->ctx, buffer.len, buffer.buf);
}

static PyObject *
pynettle_sha224_digest(pynettle_sha224 *self)
{
  uint8_t digest[SHA224_DIGEST_SIZE];

  sha224_digest(self->ctx, SHA224_DIGEST_SIZE, digest);
  return PyBytes_FromStringAndSize((const char *)digest, SHA224_DIGEST_SIZE);
}

static PyMethodDef pynettle_sha224_methods[] = {
  {"update", (PyCFunction)pynettle_sha224_update, METH_VARARGS,
   "Hash some more data"},
  {"digest", (PyCFunction)pynettle_sha224_digest, METH_NOARGS,
    "Performs final processing and extracts the message digest"},
  {NULL}
};

static PyMemberDef pynettle_sha224_members[] = {
  {"block_size", T_INT, offsetof(pynettle_sha224, block_size),
    READONLY, "The internal block size of SHA224"},
  {"digest_size", T_INT, offsetof(pynettle_sha224, digest_size),
    READONLY, "The size of a SHA224 digest"},
  {NULL}
};

static PyTypeObject pynettle_sha224_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "nettle.hash.sha224",             /* tp_name */
    sizeof(pynettle_sha224),     /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)pynettle_sha224_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "SHA224 is a variant of SHA256, with a different initial state, and with the output truncated to 224 bits, or 28 octets. ",	       /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    pynettle_sha224_methods,     /* tp_methods */
    pynettle_sha224_members,     /* tp_members */
    0,			       /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)pynettle_sha224_init, /* tp_init */
    0,                         /* tp_alloc */
    pynettle_sha224_new,	       /* tp_new */
};

static PyModuleDef hashmodule = {
  PyModuleDef_HEAD_INIT,
  "hash",
  "An interface to nettle's low level hash library",
  -1,
  NULL, NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC
PyInit_hash(void)
{
  PyObject *m = PyModule_Create(&hashmodule);
  if (m == NULL) {
    return NULL;
  }


  pynettle_sha256_Type.tp_new = PyType_GenericNew;
  if (PyType_Ready(&pynettle_sha256_Type) < 0) {
      return NULL;
  }
  Py_INCREF(&pynettle_sha256_Type);
  PyModule_AddObject(m, "sha256", (PyObject *)&pynettle_sha256_Type);


  pynettle_sha1_Type.tp_new = PyType_GenericNew;
  if (PyType_Ready(&pynettle_sha1_Type) < 0) {
      return NULL;
  }
  Py_INCREF(&pynettle_sha1_Type);
  PyModule_AddObject(m, "sha1", (PyObject *)&pynettle_sha1_Type);


  pynettle_sha224_Type.tp_new = PyType_GenericNew;
  if (PyType_Ready(&pynettle_sha224_Type) < 0) {
      return NULL;
  }
  Py_INCREF(&pynettle_sha224_Type);
  PyModule_AddObject(m, "sha224", (PyObject *)&pynettle_sha224_Type);

  return m;
}

