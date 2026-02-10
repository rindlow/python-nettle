#
# random.py
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

from c_class import CClass
from params import RandomParam


class Random(CClass):

    def __init__(self, param: RandomParam) -> None:
        CClass.__init__(self, param['name'], param['docstring'])

        lname = param["name"].lower()
        self.add_member(
            name=param['name'],
            decl=f'struct {lname}_ctx *ctx;',
            init='self->ctx = NULL;',
            dealloc='PyMem_Free (self->ctx);\nself->ctx = NULL;')
        self.add_method(
            'random',
            docs='Generate random bytes',
            args='METH_VARARGS',
            docargs='len',
            body=f'''
                int len;
                uint8_t *data;
                PyObject *bytes;
                if (! PyArg_ParseTuple (args, "i", &len))
                  {{
                    return NULL;
                  }}
                if ((data = malloc(len)) == NULL)
                  {{
                    return PyErr_NoMemory ();
                  }}
                {lname}_random (self->ctx, len, data);
                bytes = PyBytes_FromStringAndSize ((const char *) data, len);
                free(data);
                return bytes;
            ''')
        self.add_to_init_body(f'''
            ssize_t res;
            int fd;
            uint8_t seed[{param["seedsize"]}];

            if ((self->ctx = PyMem_Malloc (sizeof (struct {lname}_ctx))) \\
                == NULL)
              {{
                PyErr_NoMemory ();
                return -1;
              }}
            if ((fd = open ("/dev/random", O_RDONLY)) < 0)
              {{
                PyErr_Format (RandomError, "Failed to open /dev/random:");
                return -1;
              }}
            do
              {{
                res = read (fd, seed, {param["seedsize"]});
              }}
            while (res < 0 && errno == EAGAIN);
            if (res < 0 && errno != EAGAIN)
              {{
                PyErr_Format (RandomError, "Failed to read /dev/random:");
                return -1;
              }}''')
        if param.get('seedfunc'):
            self.add_to_init_body(f'''
            {lname}_init (self->ctx, 0, NULL);
            {lname}_seed (self->ctx, \\
                {param["seedsize"]}, seed);''')
        else:
            self.add_to_init_body(f'''
            {lname}_init (self->ctx, seed);''')
