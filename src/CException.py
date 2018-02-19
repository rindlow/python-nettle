# -*- coding: utf-8 -*-
#
# CException.py
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

    def write_reg_to_file(self, f):
        f.write('  {self.name} = PyErr_NewExceptionWithDoc ('
                '"{self.module}.{self.name}",'
                ' "{self.docs}", {self.base}, NULL);\n'
                '  if (!{self.name})\n    {{\n'
                '      return MOD_ERR_VAL;\n'
                '    }}\n  else\n    {{\n'
                '      Py_INCREF ({self.name});\n'
                '      PyModule_AddObject (m, "{self.name}", {self.name});\n'
                '    }}\n'
                .format(self=self))

    def write_python_subclass(self, f):
        f.write('{0} = _nettle.{0}\n'.format(self.name))
