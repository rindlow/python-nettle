#!/usr/bin/env python3

HASH_FILE = 'nettle_hash.c'
MOD_FILE = 'nettle.c'

hashes = (
    ('sha1', 'sha1.h', 'SHA1 is a hash function specified by NIST (The U.S. National Institute for Standards and Technology).'),
    ('sha224', 'sha2.h', 'SHA224 is a variant of SHA256, with a different initial state, and with the output truncated to 224 bits, or 28 octets. '),
    ('sha256', 'sha2.h', 'SHA256 is a member of the SHA2 family. It outputs hash values of 256 bits, or 32 octets.')
)

headers = {h: 1 for n, h, d in hashes}

with open(HASH_FILE, 'w') as f:
    f.write('#include <Python.h>\n')
    f.write('#include <structmember.h>\n')
    for header in sorted(headers):
        f.write('#include <nettle/{}>\n'.format(header))
    f.write('\n')
        
    template = open('hash_template.c').read()
    for name, header, doc in hashes:
        f.write(template.format(hash_lower=name,
                                HASH_UPPER=name.upper(),
                                docstring=doc))

with open(MOD_FILE, 'w') as f:
    f.write('#include <Python.h>\n')
    f.write('#include <structmember.h>\n\n')
    for name, header, doc in hashes:
        f.write('extern PyTypeObject pynettle_{}_Type;\n'.format(name))
    f.write('''
static PyModuleDef nettle = {
  PyModuleDef_HEAD_INIT,
  "hash",
  "An interface to the nettle low level cryptographic library",
  -1,
  NULL, NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC
PyInit_nettle(void)
{
  PyObject *m = PyModule_Create(&nettle);
  if (m == NULL) {
    return NULL;
  }
''')

    for name, header, doc in hashes:
        f.write('''
  //pynettle_{hash}_Type.tp_new = PyType_GenericNew;
  if (PyType_Ready(&pynettle_{hash}_Type) < 0) {{
      return NULL;
  }}
  Py_INCREF(&pynettle_{hash}_Type);
  PyModule_AddObject(m, "{hash}", (PyObject *)&pynettle_{hash}_Type);
'''.format(hash=name))

    f.write('  return m;\n}\n')
