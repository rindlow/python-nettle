class CModule:

    def __init__(self, name, doc, objects):
        self.name = name
        self.doc = doc
        self.objects = objects
        self.out = None

    def write_to_file(self, out):
        out.write('#if PY_MAJOR_VERSION >= 3\n'
                  '#define MOD_ERR_VAL NULL\n'
                  'static PyModuleDef {name} = {{\n'
                  '  PyModuleDef_HEAD_INIT,\n'
                  '  "{name}",\n'
                  '  "{doc}",\n'
                  '  -1,\n'
                  '  NULL, NULL, NULL, NULL, NULL\n'
                  '}};\n'
                  'PyMODINIT_FUNC\n'
                  'PyInit_{name}(void)\n'
                  '{{\n'
                  '  PyObject *m = PyModule_Create(&{name});\n'
                  '#else\n'
                  '#define MOD_ERR_VAL\n'
                  'PyMODINIT_FUNC\n'
                  'init{name}(void)\n'
                  '{{\n'
                  '  PyObject *m = Py_InitModule3("{name}", NULL, "{doc}");\n'
                  '#endif\n'
                  '  if (m == NULL) {{\n'
                  '    return MOD_ERR_VAL;\n'
                  '  }}\n'.format(name=self.name, doc=self.doc))

        for object in sorted(self.objects):
            out.write('  if (PyType_Ready(&pynettle_{object}_Type) < 0) {{\n'
                      '    return MOD_ERR_VAL;\n'
                      '  }}\n'
                      '  Py_INCREF(&pynettle_{object}_Type);\n'
                      '  PyModule_AddObject(m, "{object}",'
                      ' (PyObject *)&pynettle_{object}_Type);\n'
                      .format(object=object))
        out.write('#if PY_MAJOR_VERSION >= 3\n'
                  '  return m;\n'
                  '#endif\n'
                  '}\n')
