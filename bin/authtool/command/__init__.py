# =======================================================================================================
# This project, Intel(R) Arria(R) 10 SoC FPGA Authentication Signing Utility (GIT), is Licensed as below
# =======================================================================================================
# 
# SPDX-License-Identifier: MIT-0
# 
# Copyright (c) 2013-2021 Intel Corporation All Right Reserved
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy 
# of this software and associated documentation files (the "Software"), to deal 
# in the Software without restriction, including without limitation the rights 
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
# copies of the Software, and to permit persons to whom the Software is furnished 
# to do so.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
# IN THE SOFTWARE.

import os
import importlib

register_hooks = []

for _basename, _ext in map(os.path.splitext, os.listdir(os.path.dirname(__file__))):
    if _ext == '.py' and _basename != '__init__':
        try:
            _register_hook = getattr(importlib.import_module('.' + _basename, __package__), 'register', None)
            if _register_hook is not None:
                register_hooks.append(_register_hook)
            del _register_hook
        except Exception as _err:
            print (str(_err))
            del _err

del _basename, _ext

del importlib
del os
