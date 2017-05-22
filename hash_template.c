typedef struct {{
  PyObject_HEAD
  struct {hash_lower}_ctx *ctx;
  int digest_size;
  int block_size;
}} pynettle_{hash_lower};


static PyObject *
pynettle_{hash_lower}_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{{
  pynettle_{hash_lower} *self;

  self = (pynettle_{hash_lower} *)type->tp_alloc(type, 0);
  return (PyObject *)self;
}}

static int
pynettle_{hash_lower}_init(pynettle_{hash_lower} *self, PyObject *args, PyObject *kwds)
{{
  if ((self->ctx = PyMem_Malloc(sizeof(struct {hash_lower}_ctx))) == NULL) {{
    PyErr_NoMemory();
    return -1;
  }}
  {hash_lower}_init(self->ctx);
  self->digest_size = {HASH_UPPER}_DIGEST_SIZE;
  self->block_size = {HASH_UPPER}_BLOCK_SIZE;
  return 0;
}}

void
pynettle_{hash_lower}_dealloc(pynettle_{hash_lower} *self)
{{
  PyMem_Free(self->ctx);
  self->ctx = NULL;
}}

void
pynettle_{hash_lower}_update(pynettle_{hash_lower} *self, PyObject *args)
{{
  Py_buffer buffer;

  if (! PyArg_ParseTuple(args, "y*", &buffer)) {{
    return;
  }}
  {hash_lower}_update(self->ctx, buffer.len, buffer.buf);
}}

static PyObject *
pynettle_{hash_lower}_digest(pynettle_{hash_lower} *self)
{{
  uint8_t digest[{HASH_UPPER}_DIGEST_SIZE];

  {hash_lower}_digest(self->ctx, {HASH_UPPER}_DIGEST_SIZE, digest);
  return PyBytes_FromStringAndSize((const char *)digest, {HASH_UPPER}_DIGEST_SIZE);
}}

static PyMethodDef pynettle_{hash_lower}_methods[] = {{
  {{"update", (PyCFunction)pynettle_{hash_lower}_update, METH_VARARGS,
   "Hash some more data"}},
  {{"digest", (PyCFunction)pynettle_{hash_lower}_digest, METH_NOARGS,
    "Performs final processing and extracts the message digest"}},
  {{NULL}}
}};

static PyMemberDef pynettle_{hash_lower}_members[] = {{
  {{"block_size", T_INT, offsetof(pynettle_{hash_lower}, block_size),
    READONLY, "The internal block size of {HASH_UPPER}"}},
  {{"digest_size", T_INT, offsetof(pynettle_{hash_lower}, digest_size),
    READONLY, "The size of a {HASH_UPPER} digest"}},
  {{NULL}}
}};

static PyTypeObject pynettle_{hash_lower}_Type = {{
    PyVarObject_HEAD_INIT(NULL, 0)
    "nettle.hash.{hash_lower}",             /* tp_name */
    sizeof(pynettle_{hash_lower}),     /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)pynettle_{hash_lower}_dealloc, /* tp_dealloc */
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
    "{docstring}",	       /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    pynettle_{hash_lower}_methods,     /* tp_methods */
    pynettle_{hash_lower}_members,     /* tp_members */
    0,			       /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)pynettle_{hash_lower}_init, /* tp_init */
    0,                         /* tp_alloc */
    pynettle_{hash_lower}_new,	       /* tp_new */
}};
