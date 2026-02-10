# -*- coding: utf-8 -*-
#
# CClass.py
#
# Copyright (C) 2017, 2018 Henrik Rindlöw
#
# This file is part of python-nettle.
#
# Python-nettle is free software: you can redistribute it and/or
# modify it under the terms of either:
#
#   * the GNU Lesser General Public License as published by the Free
#     Software Foundation; either version 3 of the License, or (at your
#     option) any later version.
#
# or
#
#   * the GNU General Public License as published by the Free
#     Software Foundation; either version 2 of the License, or (at your
#     option) any later version.
#
# or both in parallel, as here.
#
# Python-nettle is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received copies of the GNU General Public License and
# the GNU Lesser General Public License along with this program.  If
# not, see http://www.gnu.org/licenses/.

import re
from typing import NotRequired, TextIO, TypedDict


class PublicClassError(Exception):
    """Error generating public class."""


class Member(TypedDict):
    name: str
    decl: str
    flags: str
    public: bool
    docs: NotRequired[str]
    init: NotRequired[str]
    alloc: NotRequired[str]
    dealloc: NotRequired[str]
    type: NotRequired[str]

class Method(TypedDict):
    name: str
    body: str
    docs: str
    args: str
    docargs: str

class MethodAlias(TypedDict):
    method: str
    alias: str
    docs: str
    args: str
    docargs: str

class GetSetter(TypedDict):
    member: str
    docs: str
    getter: str
    gbody: NotRequired[str]
    setter: str
    sbody: NotRequired[str]


indent_re = re.compile(r'''
    ^ (?P<line> \s*
        (?P<pre> \# ) ?
        (?P<code>
            (?P<nonwhite> \S) .*? ) )
        (?P<backslash> \\ \s* ) ?
        (?P<doubleslash> // \s* ) ?
    $''', re.VERBOSE)

def writeindent(f: TextIO, spaces: int, string: str, emptylines: bool = False) -> None:
    lines = string.split('\n')
    minindent = 9999
    doubleslash = False
    for line in lines:
        m = indent_re.search(line)
        if (m and
            not doubleslash and
            m.group('pre') is None and
            m.start('nonwhite') < minindent):
            minindent = m.start('nonwhite')
        doubleslash = m and m.group('doubleslash') is not None

    cont = False
    lastindent = None
    for line in lines:
        m = indent_re.search(line)
        if m:
            if m.group('pre') is not None:
                f.write(m.group('pre') + m.group('code') + '\n')
            else:
                if not cont:
                    f.write(' ' * spaces)
                if m.group('backslash') is not None:
                    f.write(m.group('line')[minindent:])
                    cont = True
                elif m.group('doubleslash') is not None:
                    lastindent = m.start('nonwhite') - minindent
                    f.write(' ' * lastindent)
                    f.write(m.group('code') + '\n')
                else:
                    if cont:
                        f.write(m.group('code') + '\n')
                    elif lastindent is not None:
                        f.write(' ' * lastindent)
                        f.write(m.group('code') + '\n')
                        lastindent = None
                    else:
                        f.write(m.group('line')[minindent:] + '\n')
                    cont = False
        elif emptylines:
            f.write('\n')

class CClass:

    def __init__(self, name: str, docs: str, args: str = '') -> None:
        self.name = name
        self.docs = docs
        self.members: list[Member] = []
        self.methods: list[Method] = []
        self.method_aliases: list[MethodAlias] = []
        self.init_body: list[str] = []
        self.richcompare: str | None = None
        self.getsetters: list[GetSetter] = []
        self.args = args

    def write_python_subclass(self, f: TextIO) -> None:
        f.write(f'{self.name} = _nettle.{self.name}\n')

    def write_class_struct_to_file(self, f: TextIO) -> None:
        f.write('typedef struct\n{'
                '\n  PyObject_HEAD\n')
        f.writelines(f"  {member['decl']};" for member in self.members)
        f.write(f'}} pynettle_{self.name};\n')

    def write_new(self, f: TextIO) -> None:
        writeindent(f, 0, f'''
            static PyObject *
            pynettle_{self.name}_new (PyTypeObject * type, PyObject * args, \\
                                 PyObject * kwds)
            {{\n
              pynettle_{self.name} *self = (pynettle_{self.name} *) type->tp_alloc \\
                (type, 0);
            ''' )
        for member in self.members:
            if 'alloc' in member:
                writeindent(f, 2, member['alloc'])
        writeindent(f, 2, 'return (PyObject *) self;')
        writeindent(f, 0, '}')

    def write_init(self, f: TextIO) -> None:
        writeindent(f, 0, f'''
            static int
            pynettle_{self.name}_init (pynettle_{self.name} * self, PyObject * args, \\
                                  PyObject * kwds)
            {{''')
        for member in self.members:
            if 'init' in member:
                writeindent(f, 2, member['init'])
        for part in self.init_body:
            writeindent(f, 2, part)
        writeindent(f, 2, 'return 0;')
        writeindent(f, 0, '}')

    def write_dealloc(self, f: TextIO) -> None:
        writeindent(f, 0, f'''
            static void
            pynettle_{self.name}_dealloc (pynettle_{self.name} * self)
            {{''')
        for member in self.members:
            if 'dealloc' in member:
                writeindent(f, 2, member['dealloc'])
        writeindent(f, 0, '}')

    def write_methods(self, f: TextIO) -> None:
        for method in self.methods:
            writeindent(f, 0, f'''
                static PyObject *
                pynettle_{self.name}_{method['name']} (pynettle_{self.name} * self, \\
                                          PyObject * args, PyObject * kwds)
                {{''')
            writeindent(f, 2, method['body'])
            writeindent(f, 0, '}')

    def write_method_def(self, f: TextIO) -> None:
        writeindent(f, 0, f'static PyMethodDef pynettle_{self.name}_methods[] = {{')
        for method in self.methods:
            writeindent(f, 2, '''
                {{ "{method}", (PyCFunction) pynettle_{name}_{method}, \\
                   {args}, "{docstring}" }},
                '''.format(name=self.name, method=method['name'],
                           args=method['args'], docstring=method['docs']))
        for method in self.method_aliases:
            writeindent(f, 2, f'''
                {{ "{method['alias']}", (PyCFunction) \\
                   pynettle_{self.name}_{method['method']}, \\
                   {method['args']}, "{method['docs']}" }},
                ''')
        writeindent(f, 2, '{ NULL }')
        writeindent(f, 0, '};')

    def write_member_def(self, f: TextIO) -> None:
        if len([m for m in self.members if m['public']]) > 0:
            writeindent(f, 0, f'''
                static PyMemberDef pynettle_{self.name}_members[] = {{
                ''')
            for member in self.members:
                if member['public']:
                    if 'type' not in member or 'docs' not in member:
                        raise PublicClassError(member['name'])
                    writeindent(f, 2, f'''
                        {{ "{member['name']}", {member['type']}, offsetof  \\
                           (pynettle_{self.name}, \\
                           {member['name']}), {member['flags']}, "{member['docs']}" }},
                        ''')
            writeindent(f, 2, '{ NULL }')
            writeindent(f, 0, '};')

    def write_richcompare(self, f: TextIO) -> None:
        if self.richcompare is not None:
            writeindent(f, 0, f'''
                PyObject *
                pynettle_{self.name}_richcompare (PyObject *a, PyObject *b, int op)
                {{''')
            writeindent(f, 2, self.richcompare)
            writeindent(f, 0, '}')

    def write_getsetters(self, f: TextIO) -> None:
        if self.getsetters:
            for gs in self.getsetters:
                if 'gbody' in gs:
                    writeindent(f, 0, '''
                        static PyObject *
                        {getter} (pynettle_{name} * self, void * closure)
                        {{'''.format(getter=gs['getter'], name=self.name))
                    writeindent(f, 2, gs['gbody'])
                    writeindent(f, 0, '}')

                if 'sbody' in gs:
                    writeindent(f, 0, '''
                        static PyObject *
                        {setter} (pynettle_{name} * self, PyObject * value, \\
                                  void * closure)
                        {{'''.format(setter=gs['setter'], name=self.name))
                    writeindent(f, 2, gs['sbody'])
                    writeindent(f, 0, '}')

            writeindent(f, 0, f'''
                static PyGetSetDef pynettle_{self.name}_getsetters[] = {{
                ''')
            for gs in self.getsetters:
                writeindent(f, 2, '''
                {{ "{member}",
                  (getter){getter},
                  (setter){setter},
                  "{docs}",
                  NULL }},'''.format(**gs))
            writeindent(f, 2, '{ NULL }')
            writeindent(f, 0, '};')

    def write_type(self, f: TextIO) -> None:
        if len([m for m in self.members if m['public']]) > 0:
            members = f'pynettle_{self.name}_members'
        else:
            members = 0
        if self.richcompare is None:
            richcompare = 0
        else:
            richcompare = f'pynettle_{self.name}_richcompare'
        if self.getsetters:
            getset = f'pynettle_{self.name}_getsetters'
        else:
            getset = 0
        writeindent(f, 0, f'''
            PyTypeObject pynettle_{self.name}_Type = {{
              PyVarObject_HEAD_INIT(NULL, 0)
              "nettle.{self.name}",			      /* tp_name */
              sizeof (pynettle_{self.name}),		      /* tp_basicsize */
              0,				      /* tp_itemsize */
              (destructor)pynettle_{self.name}_dealloc,    /* tp_dealloc */
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
              ''')
        writeindent(f, 0, f'''
              Py_TPFLAGS_DEFAULT |
              Py_TPFLAGS_BASETYPE,                    /* tp_flags */
              "{self.docs}",			      /* tp_doc */
              0,				      /* tp_traverse */
              0,				      /* tp_clear */
              {richcompare},			      /* tp_richcompare */
              0,				      /* tp_weaklistoffset */
              0,				      /* tp_iter */
              0,				      /* tp_iternext */
              pynettle_{self.name}_methods,		      /* tp_methods */
              {members},		              /* tp_members */
              {getset},				      /* tp_getset */
              0,				      /* tp_base */
              0,				      /* tp_dict */
              0,				      /* tp_descr_get */
              0,				      /* tp_descr_set */
              0,				      /* tp_dictoffset */
              (initproc)pynettle_{self.name}_init,	      /* tp_init */
              0,				      /* tp_alloc */
              pynettle_{self.name}_new,                    /* tp_new */
            }};
            ''')

    def write_to_file(self, f: TextIO) -> None:
        f.write(f'\n/******************** {self.name} ********************/\n')
        self.write_new(f)
        self.write_init(f)
        self.write_dealloc(f)
        self.write_methods(f)
        self.write_method_def(f)
        self.write_member_def(f)
        self.write_richcompare(f)
        self.write_getsetters(f)
        self.write_type(f)

    def write_decl_to_file(self, f: TextIO, extern: bool=False) -> None:
        if extern:
            self.write_class_struct_to_file(f)
            f.write('extern ')
            f.write(f'PyTypeObject pynettle_{self.name}_Type;\n')

    def write_reg_to_file(self, f: TextIO) -> None:
        f.write(f'  if (PyType_Ready (&pynettle_{self.name}_Type) < 0)\n'
                '    {\n'
                '      return MOD_ERR_VAL;\n'
                '    }\n'
                f'  Py_INCREF (&pynettle_{self.name}_Type);\n'
                f'  PyModule_AddObject (m, "{self.name}",'
                f' (PyObject *) &pynettle_{self.name}_Type);\n',
                )

    def add_member(self, name: str, decl: str, init: str | None = None,
                   ctype: str | None = None, alloc: str | None = None,
                   dealloc: str | None = None, docs: str | None = None,
                   flags: str = '0', public: bool = False) -> None:
        member: Member = {'name': name, 'decl': decl, 'flags': flags, 'public': public }
        if init is not None:
            member['init'] = init
        if alloc is not None:
            member['alloc'] = alloc
        if dealloc is not None:
            member['dealloc'] = dealloc
        if ctype is not None:
            member['type'] = ctype
        if docs is not None:
            member['docs'] = docs
        self.members.append(member)

    def add_method(self, name: str, body: str, docs: str, args: str,
                   docargs: str = '') -> None:
        self.methods.append({'name': name, 'body': body,
                             'docs': docs, 'args': args,
                             'docargs': docargs})

    def add_method_alias(self, method: str, alias: str, docs: str, args: str,
                         docargs: str = '') -> None:
        self.method_aliases.append({'method': method, 'alias': alias,
                             'docs': docs, 'args': args,
                             'docargs': docargs})

    def add_to_init_body(self, code: str) -> None:
        self.init_body.append(code)

    def add_richcompare(self, body: str) -> None:
        self.richcompare = body

    def add_getsetter(self, member: str, gbody: str | None = None,
                      sbody: str | None = None, docs: str = '') -> None:
        gs: GetSetter = {
            'member': member, 'docs': docs,
            'getter': 'NULL', 'setter': 'NULL' }
        if gbody is not None:
            gs['getter'] = f'pynettle_{self.name}_get{member}'
            gs['gbody'] = gbody
        if sbody is not None:
            gs['setter'] = f'pynettle_{self.name}_set{member}'
            gs['sbody'] = sbody
        self.getsetters.append(gs)

    def add_bufferparse_to_init(self, buffers: list[str]) -> None:
        kwlist = f'''{{"{'", "'.join(buffers)}", NULL}}'''
        nullify='//\n'.join([f'{b}.buf = NULL; {b}.len = 0;' for b in buffers])
        fmt = '|' + 'z*' * len(buffers)
        pointers = ', '.join([f'&{b}' for b in buffers])
        self.add_to_init_body(f'''
              static char *kwlist[] = {kwlist};
              Py_buffer {', '.join(buffers)};
              {nullify}
              if (! PyArg_ParseTupleAndKeywords (args, kwds, "{fmt}", \\
                                                 kwlist,
                                                 {pointers}))
                {{
                  return -1;
                }}
            ''')

    def write_docs_to_file(self, f: TextIO) -> None:
        writeindent(f, 0, f'''
            :class:`{self.name}`
            -------------------------------------------

            {self.docs}


            .. class:: {self.name}({self.args})

        ''', emptylines=True)

        if len([m for m in self.members if m['public']]) > 0:
            writeindent(f, 0, '''


                Class attributes are:


            ''')

        for member in self.members:
            if member['public']:
                if 'docs' not in member:
                    raise PublicClassError(member['name'])
                writeindent(f, 0, f'''
                .. attribute:: {self.name}.{member['name']}


                   {member['docs']}


                ''', emptylines=True)

        for gs in self.getsetters:
            writeindent(f, 0, f'''
            .. attribute:: {self.name}.{gs['member']}


               {gs['member']}

            ''', emptylines=True)

        writeindent(f, 0, '''
            Instance methods:

        ''', emptylines=True)

        for method in self.methods:
            writeindent(f, 0, '''
            .. method:: {name}.{mname}({args})

               {docs}

            '''.format(name=self.name, mname=method['name'],
                       args=method['docargs'],
                       docs=method['docs']), emptylines=True)
        for method in self.method_aliases:
            writeindent(f, 0, '''
            .. method:: {name}.{mname}({args})

               {docs}

            '''.format(name=self.name, mname=method['alias'],
                       args=method['docargs'],
                       docs=method['docs']), emptylines=True)
