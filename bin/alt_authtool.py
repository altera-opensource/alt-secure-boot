#!/usr/bin/env python
# =======================================================================================================
# This project, Intel(R) Arria(R) 10 SoC FPGA Authentication Signing Utility (GIT), is Licensed as below
# =======================================================================================================
# 
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

__copyright__ = "Copyright (c) 2013-2021 Intel Corporation All Right Reserved"
__p4_file_header__ = ""
__version__ = "$Revision: #11 $"
__date__ = "$Date: 2020/05/20 $"


import argparse
import os
import sys

#basedir = os.path.dirname(__file__)
#basedir = os.path.abspath(basedir)
#sys.path.insert(0, os.path.join(basedir, "extlib", "pyasn1-0.4.8-py3.6.egg"))
#sys.path.insert(0, os.path.join(basedir, "extlib", "pyasn1_modules-0.2.7-py3.6.egg"))

from authtool.command import register_hooks

def main(argv):
    result = -1

    try:
	## FB357820 pass in prog argument to update help menu usage name
        parser = argparse.ArgumentParser(prog='alt-secure-boot')
        subparsers = parser.add_subparsers(title='Available subcommands')

        for register_command in register_hooks:
            register_command(subparsers)

        args = parser.parse_args(argv)
        result = args.operation(args)

    except Exception as err:
        print (str(err))

    return result

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
