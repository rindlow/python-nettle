class CClass:
    def __init__(self, name, docs):
        self.name = name
        self.docs = docs
        self.members = []
        self.methods = []
        self.init_body = ''
        self.richcompare = None
        self.getsetters = []
        self.out = None

    def write_class_struct_to_file(self, f):
        f.write('typedef struct\n{{'
                '\n  PyObject_HEAD\n'.format(self.name))
        for member in self.members:
            f.write('  {};\n'.format(member['decl']))
        f.write('}} pynettle_{};\n'.format(self.name))

    def write_new(self):
        self.out.write('static PyObject *\n'
                       'pynettle_{name}_new (PyTypeObject * type,'
                       ' PyObject * args, PyObject * kwds)\n'
                       '{{\n'
                       '  pynettle_{name} *self;\n'
                       '  self = (pynettle_{name} *)'
                       ' type->tp_alloc (type, 0);\n'
                       .format(name=self.name))
        for member in self.members:
            if member['alloc'] is not None:
                self.out.write('  {}\n'.format(member['alloc']))
        self.out.write('  return (PyObject *) self;\n}\n\n')

    def write_init(self):
        self.out.write('static int\n'
                       'pynettle_{name}_init (pynettle_{name} * self,'
                       ' PyObject * args, PyObject * kwds)\n'
                       '{{\n'.format(name=self.name))
        for member in self.members:
            if member['init'] is not None:
                self.out.write('  {}\n'.format(member['init']))
        if self.init_body != '':
            self.out.write(self.init_body)
        self.out.write('  return 0;\n}\n\n')

    def write_dealloc(self):
        self.out.write('static void\n'
                       'pynettle_{name}_dealloc (pynettle_{name} * self)\n'
                       '{{\n'.format(name=self.name))
        for member in self.members:
            if member['dealloc'] is not None:
                self.out.write('  {}\n'.format(member['dealloc']))
        self.out.write('}\n\n')

    def write_methods(self):
        for method in self.methods:
            self.out.write('static PyObject *\n'
                           'pynettle_{name}_{method} (pynettle_{name} * self,'
                           ' PyObject * args, PyObject * kwds)\n'
                           '{{'.format(name=self.name, method=method['name']))
            self.out.write(method['body'] + '}\n\n')

    def write_method_def(self):
        self.out.write('static PyMethodDef pynettle_{name}_methods[] = {{\n'
                       .format(name=self.name))
        for method in self.methods:
            self.out.write('  {{"{method}",'
                           ' (PyCFunction) pynettle_{name}_{method}, {args},'
                           ' "{docstring}"}},\n'.format(
                               name=self.name,
                               method=method['name'],
                               args=method['args'],
                               docstring=method['docs']))
        self.out.write('  {NULL}\n};\n\n')

    def write_member_def(self):
        if len([m for m in self.members if m['public']]) > 0:
            self.out.write('static PyMemberDef pynettle_{name}_members[]'
                           ' = {{\n'.format(name=self.name))
            for member in self.members:
                if member['public']:
                    self.out.write('  {{"{member}", {type},'
                                   ' offsetof (pynettle_{name}, {member}),'
                                   ' {flags}, "{docstring}"}},\n'
                                   .format(name=self.name,
                                           member=member['name'],
                                           flags=member['flags'],
                                           type=member['type'],
                                           docstring=member['docs']))
            self.out.write('  {NULL}\n};\n\n')

    def write_richcompare(self):
        if self.richcompare is not None:
            self.out.write('PyObject *\npynettle_{}_richcompare(PyObject *a,'
                           ' PyObject *b, int op)\n{{\n{}\n}}'''
                           .format(self.name, self.richcompare))

    def write_getsetters(self):
        if self.getsetters:
            for gs in self.getsetters:
                if gs['gbody'] is not None:
                    self.out.write('static PyObject *\n'
                                   '{getter} (pynettle_{name}'
                                   ' *self, void *closure)\n{{\n{body}\n}}\n'
                                   .format(getter=gs['getter'],
                                           name=self.name,
                                           body=gs['gbody']))
                if gs['sbody'] is not None:
                    self.out.write('static PyObject *\n'
                                   '{setter} (pynettle_{name}'
                                   ' *self, PyObject *value, void *closure)'
                                   '\n{{\n{body}\n}}\n'
                                   .format(setter=gs['setter'],
                                           name=self.name,
                                           body=gs['sbody']))
            self.out.write('static PyGetSetDef pynettle_{}_getsetters[] = {{\n'
                           .format(self.name))
            for gs in self.getsetters:
                self.out.write('    {{"{member}", '
                               '(getter){getter}, (setter){setter},'
                               ' "{docs}", NULL}},\n'.format(**gs))
            self.out.write('    {NULL}\n};\n')

    def write_type(self):
        if len([m for m in self.members if m['public']]) > 0:
            members = 'pynettle_{}_members'.format(self.name)
        else:
            members = 0
        if self.richcompare is None:
            richcompare = 0
            have_richcompare = ''
        else:
            richcompare = 'pynettle_{}_richcompare'.format(self.name)
            have_richcompare = '\n#if PY_MAJOR_VERSION < 3\n' \
                               '    Py_TPFLAGS_HAVE_RICHCOMPARE |\n' \
                               '#endif'
        if self.getsetters:
            getset = 'pynettle_{}_getsetters'.format(self.name)
        else:
            getset = 0
        self.out.write('''PyTypeObject pynettle_{name}_Type = {{
    PyVarObject_HEAD_INIT(NULL, 0)
    "nettle.{name}",			 /* tp_name */
    sizeof(pynettle_{name}),		 /* tp_basicsize */
    0,					 /* tp_itemsize */
    (destructor)pynettle_{name}_dealloc,	/* tp_dealloc */
    0,					 /* tp_print */
    0,					 /* tp_getattr */
    0,					 /* tp_setattr */
    0,					 /* tp_reserved */
    0,					 /* tp_repr */
    0,					 /* tp_as_number */
    0,					 /* tp_as_sequence */
    0,					 /* tp_as_mapping */
    0,					 /* tp_hash  */
    0,					 /* tp_call */
    0,					 /* tp_str */
    0,					 /* tp_getattro */
    0,					 /* tp_setattro */
    0,					 /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | {have_richcompare}
    Py_TPFLAGS_BASETYPE,		 /* tp_flags */
    "{docstring}",			 /* tp_doc */
    0,					 /* tp_traverse */
    0,					 /* tp_clear */
    {richcompare},			 /* tp_richcompare */
    0,					 /* tp_weaklistoffset */
    0,					 /* tp_iter */
    0,					 /* tp_iternext */
    pynettle_{name}_methods,		 /* tp_methods */
    {members},		                 /* tp_members */
    {getset},				 /* tp_getset */
    0,					 /* tp_base */
    0,					 /* tp_dict */
    0,					 /* tp_descr_get */
    0,					 /* tp_descr_set */
    0,					 /* tp_dictoffset */
    (initproc)pynettle_{name}_init,	 /* tp_init */
    0,					 /* tp_alloc */
    pynettle_{name}_new,		 /* tp_new */

}};
'''.format(name=self.name, docstring=self.docs, members=members,
           richcompare=richcompare, have_richcompare=have_richcompare,
           getset=getset))

    def write_to_file(self, f):
        self.out = f
        self.out.write('\n/******************** {} ********************/\n'
                       .format(self.name))
        self.write_new()
        self.write_init()
        self.write_dealloc()
        self.write_methods()
        self.write_method_def()
        self.write_member_def()
        self.write_richcompare()
        self.write_getsetters()
        self.write_type()

    def write_decl_to_file(self, f, extern=False):
        if extern:
            self.write_class_struct_to_file(f)
            f.write('extern ')
            f.write('PyTypeObject pynettle_{}_Type;\n'.format(self.name))

    def write_reg_to_file(self, f):
        f.write('  if (PyType_Ready (&pynettle_{name}_Type) < 0) {{\n'
                '    return MOD_ERR_VAL;\n'
                '  }}\n'
                '  Py_INCREF (&pynettle_{name}_Type);\n'
                '  PyModule_AddObject (m, "{name}",'
                ' (PyObject *) &pynettle_{name}_Type);\n'
                .format(name=self.name))

    def add_member(self, name, decl, init=None, type=None, alloc=None,
                   dealloc=None, docs=None, flags=0, public=False):
        self.members.append({'name': name, 'decl': decl, 'docs': docs,
                             'init': init, 'alloc': alloc, 'dealloc': dealloc,
                             'type': type, 'flags': flags, 'public': public})

    def add_method(self, name, body, docs, args):
        self.methods.append({'name': name, 'body': body,
                             'docs': docs, 'args': args})

    def add_to_init_body(self, code):
        self.init_body += code

    def add_richcompare(self, body):
        self.richcompare = body

    def add_getsetter(self, member, gbody=None, sbody=None, docs=None):
        if gbody is None:
            getter = 'NULL'
        else:
            getter = 'pynettle_{}_get{}'.format(self.name, member)
        if sbody is None:
            setter = 'NULL'
        else:
            setter = 'pynettle_{}_set{}'.format(self.name, member)
        self.getsetters.append({'member': member, 'docs': docs,
                                'getter': getter, 'gbody': gbody,
                                'setter': setter, 'sbody': sbody})
