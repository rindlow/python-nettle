# -*- coding: utf-8 -*-
#
# CModule.py
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

from typing import TextIO

from protocols import Object


class CModule:

    def __init__(self, name: str, doc: str, objects: list[Object]) -> None:
        self.name = name
        self.doc = doc
        self.objects = objects
        self.out = None

    def write_to_file(self, out: TextIO) -> None:
        out.write('#define MOD_ERR_VAL NULL\n'
                  f'static PyModuleDef {self.name} = {{\n'
                  '  PyModuleDef_HEAD_INIT,\n'
                  f'  "{self.name}",\n'
                  f'  "{self.doc}",\n'
                  '  -1,\n'
                  '  NULL, NULL, NULL, NULL, NULL\n'
                  '};\n'
                  'PyMODINIT_FUNC\n'
                  f'PyInit_{self.name} (void)\n'
                  '{\n'
                  f'  PyObject *m = PyModule_Create (&{self.name});\n'
                  '  if (m == NULL) {\n'
                  '    return MOD_ERR_VAL;\n'
                  '  }\n')

        for obj in sorted(self.objects, key=lambda o: o.name):
            obj.write_reg_to_file(out)

        out.write('  return m;\n'
                  '}\n')
