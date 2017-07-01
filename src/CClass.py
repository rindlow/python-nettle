import re


class CClass:

    indent_re = re.compile(r'''
        ^ (?P<line> \s*
            (?P<pre> \# ) ?
            (?P<code>
              (?P<nonwhite> \S) .*? ) )
          (?P<backslash> \\ \s* ) ?
        $''', re.X)

    def __init__(self, name, docs):
        self.name = name
        self.docs = docs
        self.members = []
        self.methods = []
        self.init_body = ''
        self.richcompare = None
        self.getsetters = []
        self.out = None
        self.to_be_subclassed = False

    def writeindent(self, spaces, str):
        lines = str.split('\n')
        minindent = 9999
        for line in lines:
            m = self.indent_re.search(line)
            if m and m.group('pre') is None:
                if m.start('nonwhite') < minindent:
                    minindent = m.start('nonwhite')
        cont = False
        for line in lines:
            m = self.indent_re.search(line)
            if m:
                if m.group('pre') is not None:
                    self.out.write(m.group('pre') + m.group('code') + '\n')
                else:
                    if not cont:
                        self.out.write(' ' * spaces)
                    if m.group('backslash') is not None:
                        self.out.write(m.group('line')[minindent:])
                        cont = True
                    else:
                        if cont:
                            self.out.write(m.group('code') + '\n')
                        else:
                            self.out.write(m.group('line')[minindent:] + '\n')
                        cont = False

    def write_python_subclass(self, f):
        if not self.to_be_subclassed:
            f.write('{0} = _nettle.{0}\n'.format(self.name))
        
    def write_class_struct_to_file(self, f):
        f.write('typedef struct\n{{'
                '\n  PyObject_HEAD\n'.format(self.name))
        for member in self.members:
            f.write('  {};\n'.format(member['decl']))
        f.write('}} pynettle_{};\n'.format(self.name))

    def write_new(self):
        self.writeindent(0, '''
            static PyObject *
            pynettle_{name}_new (PyTypeObject * type, PyObject * args, \\
                                 PyObject * kwds)
            {{\n
              pynettle_{name} *self = (pynettle_{name} *) type->tp_alloc \\
                (type, 0);
            ''' .format(name=self.name))
        for member in self.members:
            if member['alloc'] is not None:
                self.writeindent(2, member['alloc'])
        self.writeindent(2, 'return (PyObject *) self;')
        self.writeindent(0, '}')

    def write_init(self):
        self.writeindent(0, '''
            static int
            pynettle_{name}_init (pynettle_{name} * self, PyObject * args, \\
                                  PyObject * kwds)
            {{'''.format(name=self.name))
        for member in self.members:
            if member['init'] is not None:
                self.writeindent(2, member['init'])
        if self.init_body != '':
            self.writeindent(2, self.init_body)
        self.writeindent(2, 'return 0;')
        self.writeindent(0, '}')

    def write_dealloc(self):
        self.writeindent(0, '''
            static void
            pynettle_{name}_dealloc (pynettle_{name} * self)
            {{'''.format(name=self.name))
        for member in self.members:
            if member['dealloc'] is not None:
                self.writeindent(2, member['dealloc'])
        self.writeindent(0, '}')

    def write_methods(self):
        for method in self.methods:
            self.writeindent(0, '''
                static PyObject *
                pynettle_{name}_{method} (pynettle_{name} * self, \\
                                          PyObject * args, PyObject * kwds)
                {{'''.format(name=self.name, method=method['name']))
            self.writeindent(2, method['body'])
            self.writeindent(0, '}')

    def write_method_def(self):
        self.writeindent(0, 'static PyMethodDef pynettle_{name}_methods[] = {{'
                         .format(name=self.name))
        for method in self.methods:
            self.writeindent(2, '''
                {{ "{method}", (PyCFunction) pynettle_{name}_{method}, \\
                   {args}, "{docstring}" }},
                '''.format(name=self.name, method=method['name'],
                           args=method['args'], docstring=method['docs']))
        self.writeindent(2, '{ NULL }')
        self.writeindent(0, '};')

    def write_member_def(self):
        if len([m for m in self.members if m['public']]) > 0:
            self.writeindent(0, '''
                static PyMemberDef pynettle_{name}_members[] = {{
                '''.format(name=self.name))
            for member in self.members:
                if member['public']:
                    self.writeindent(2, '''
                        {{ "{member}", {type}, offsetof (pynettle_{name}, \\
                           {member}), {flags}, "{docstring}" }},
                        '''.format(name=self.name,
                                   member=member['name'],
                                   flags=member['flags'],
                                   type=member['type'],
                                   docstring=member['docs']))
            self.writeindent(2, '{ NULL }')
            self.writeindent(0, '};')

    def write_richcompare(self):
        if self.richcompare is not None:
            self.writeindent(0, '''
                PyObject *
                pynettle_{}_richcompare (PyObject *a, PyObject *b, int op)
                {{'''.format(self.name))
            self.writeindent(2, self.richcompare)
            self.writeindent(0, '}')

    def write_getsetters(self):
        if self.getsetters:
            for gs in self.getsetters:
                if gs['gbody'] is not None:
                    self.writeindent(0, '''
                        static PyObject *
                        {getter} (pynettle_{name} * self, void * closure)
                        {{'''.format(getter=gs['getter'], name=self.name))
                    self.writeindent(2, gs['gbody'])
                    self.writeindent(0, '}')

                if gs['sbody'] is not None:
                    self.writeindent(0, '''
                        static PyObject *
                        {setter} (pynettle_{name} * self, PyObject * value, \\
                                  void * closure)
                        {{'''.format(setter=gs['setter'], name=self.name))
                    self.writeindent(2, gs['sbody'])
                    self.writeindent(0, '}')

            self.writeindent(0, '''
                static PyGetSetDef pynettle_{}_getsetters[] = {{
                '''.format(self.name))
            for gs in self.getsetters:
                self.writeindent(2, '''
                {{ "{member}",
                  (getter){getter},
                  (setter){setter},
                  "{docs}",
                  NULL }},'''.format(**gs))
            self.writeindent(2, '{ NULL }')
            self.writeindent(0, '};')

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
            have_richcompare = '''
                #if PY_MAJOR_VERSION < 3
                Py_TPFLAGS_HAVE_RICHCOMPARE |
                #endif
                '''
        if self.getsetters:
            getset = 'pynettle_{}_getsetters'.format(self.name)
        else:
            getset = 0
        self.writeindent(0, '''
            PyTypeObject pynettle_{name}_Type = {{
              PyVarObject_HEAD_INIT(NULL, 0)
              "nettle.{name}",			      /* tp_name */
              sizeof (pynettle_{name}),		      /* tp_basicsize */
              0,				      /* tp_itemsize */
              (destructor)pynettle_{name}_dealloc,    /* tp_dealloc */
              0,				      /* tp_print */
              0,				      /* tp_getattr */
              0,				      /* tp_setattr */
              0,				      /* tp_reserved */
              0,				      /* tp_repr */
              0,				      /* tp_as_number */
              0,				      /* tp_as_sequence */
              0,				      /* tp_as_mapping */
              0,				      /* tp_hash  */
              0,				      /* tp_call */
              0,				      /* tp_str */
              0,				      /* tp_getattro */
              0,				      /* tp_setattro */
              0,				      /* tp_as_buffer */
              '''.format(name=self.name))
        self.writeindent(2, have_richcompare)
        self.writeindent(0, '''
              Py_TPFLAGS_DEFAULT |
              Py_TPFLAGS_BASETYPE,                    /* tp_flags */
              "{docstring}",			      /* tp_doc */
              0,				      /* tp_traverse */
              0,				      /* tp_clear */
              {richcompare},			      /* tp_richcompare */
              0,				      /* tp_weaklistoffset */
              0,				      /* tp_iter */
              0,				      /* tp_iternext */
              pynettle_{name}_methods,		      /* tp_methods */
              {members},		              /* tp_members */
              {getset},				      /* tp_getset */
              0,				      /* tp_base */
              0,				      /* tp_dict */
              0,				      /* tp_descr_get */
              0,				      /* tp_descr_set */
              0,				      /* tp_dictoffset */
              (initproc)pynettle_{name}_init,	      /* tp_init */
              0,				      /* tp_alloc */
              pynettle_{name}_new,                    /* tp_new */
            }};
            '''.format(name=self.name,
                       docstring=self.docs,
                       members=members,
                       richcompare=richcompare,
                       have_richcompare=have_richcompare,
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
        f.write('  if (PyType_Ready (&pynettle_{name}_Type) < 0)\n'
                '    {{\n'
                '      return MOD_ERR_VAL;\n'
                '    }}\n'
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
