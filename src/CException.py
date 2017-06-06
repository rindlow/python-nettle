class CException:

    def __init__(self, name, module, docs, base):
        self.name = name
        self.module = module
        self.docs = docs
        self.base = base

    def write_decl_to_file(self, f, extern=False):
        if extern:
            f.write('extern ')
        f.write('PyObject *{};\n'.format(self.name))

    def write_to_file(self, f):
        f.write('  {self.name} = PyErr_NewExceptionWithDoc('
                '    "{self.module}.{self.name}",\n'
                '    "{self.docs}",\n {self.base}, NULL);\n'
                '  if (! {self.name}) {{\n'
                '    return MOD_ERR_VAL;\n'
                '  }} else {{\n'
                '    Py_INCREF({self.name});\n'
                '    PyModule_AddObject(m, "{self.name}", {self.name});\n'
                '  }}\n'
                .format(self=self))
