#!/usr/bin/env python3

hashes = {'sha1': 'SHA1 is a hash function specified by NIST (The U.S. National Institute for Standards and Technology).',
          'sha224': 'SHA224 is a variant of SHA256, with a different initial state, and with the output truncated to 224 bits, or 28 octets. ',
          'sha256': 'SHA256 is a member of the SHA2 family. It outputs hash values of 256 bits, or 32 octets.'}

print('''#include <Python.h>
#include "structmember.h"
#include <nettle/sha1.h>
#include <nettle/sha2.h>
''')

template = open('hash_template.c').read()
for name, doc in hashes.items():
    print(template.format(hash_lower=name, HASH_UPPER=name.upper(),
                          docstring=doc))


print('''static PyModuleDef hashmodule = {
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
''')

for hash in hashes:
    print('''
  pynettle_{hash}_Type.tp_new = PyType_GenericNew;
  if (PyType_Ready(&pynettle_{hash}_Type) < 0) {{
      return NULL;
  }}
  Py_INCREF(&pynettle_{hash}_Type);
  PyModule_AddObject(m, "{hash}", (PyObject *)&pynettle_{hash}_Type);
'''.format(hash=hash))

print('''  return m;
}
''')
