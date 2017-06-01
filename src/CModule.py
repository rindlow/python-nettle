class CModule:

    def __init__(self, name, objects):
        self.name = name
        self.objects = objects
        self.out = None

    def write_to_file(self, out):
        out.write('static PyModuleDef {name} = {{\n'
                  '  PyModuleDef_HEAD_INIT,\n'
                  '  "{name}",\n'
                  '  "An interface to the {name} low level'
                  ' cryptographic library",\n'
                  '  -1,\n'
                  '  NULL, NULL, NULL, NULL, NULL\n'
                  '}};\n'
                  'PyMODINIT_FUNC\n'
                  'PyInit_{name}(void)\n'
                  '{{\n'
                  '  PyObject *m = PyModule_Create(&{name});\n'
                  '  if (m == NULL) {{\n'
                  '    return NULL;\n'
                  '  }}\n'.format(name=self.name))

        for object in sorted(self.objects):
            out.write('  if (PyType_Ready(&pynettle_{object}_Type) < 0) {{\n'
                      '    return NULL;\n'
                      '  }}\n'
                      '  Py_INCREF(&pynettle_{object}_Type);\n'
                      '  PyModule_AddObject(m, "{object}",'
                      ' (PyObject *)&pynettle_{object}_Type);\n'
                      .format(object=object))
        out.write('  return m;\n}\n')
