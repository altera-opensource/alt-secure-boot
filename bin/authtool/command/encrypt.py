#!/usr/bin/env python
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

import argparse
import os
import struct
import subprocess
import traceback
from distutils.spawn import find_executable
from time import time

from authtool.utils import new_tempfile, delete_tempfiles
from authtool.authheader import (AuthHeader, is_pheader_image, simple_checksum, bytes_to_alignment,
                                 ALTR_6XS1_COMMON_AUTHHEADER_FLAGS_MUST_DECRYPT,
                                 ALTR_6XS1_MAX_AUTH_IMAGE_LENGTH,
                                 ALTR_COMMON_AUTH_IMAGE_DECRYPT,
                                 ALT_COMMON_AUTH_MAGIC,
                                 ALT_COMMON_AUTH_VERSION,
                                 AUTH_HEADER_ALIGN,
                                 AUTH_IMAGE_ALIGN)

def do_encrypt(args):
    try:
        do_encrypt_process(args)
    except Exception:
        print(traceback.format_exc())

def get_encrypted_blob(pimage, keyfile, non_volatile_key):
    output_encrypted_file = new_tempfile() + '.ebin'
    cmd = ['quartus_cpf', '-c',
           '-k', keyfile,
           '-o', 'non_volatile_key={}'.format('on' if non_volatile_key else 'off'),
           pimage, output_encrypted_file]

    with open(os.devnull, 'wb', 0) as bitbucket:
        if subprocess.call(cmd, stdout=bitbucket):
            raise ValueError('Command failed: {}'.format(' '.join(cmd)))
        else:
            return open(output_encrypted_file, 'rb').read()

def do_encrypt_process(args):
    if not is_pheader_image(open(args.inputfile, "rb").read()):
        raise ValueError("Format of input image not recognized.")

    encrypted_blob = get_encrypted_blob(args.inputfile, args.key, args.non_volatile)
    encrypted_blob_length = len(encrypted_blob)

    output = open(args.outputfile, 'wb')
    header = AuthHeader()

    header.sec_header.magic = ALT_COMMON_AUTH_MAGIC
    header.sec_header.version = ALT_COMMON_AUTH_VERSION
    header.sec_header.flags |= ALTR_6XS1_COMMON_AUTHHEADER_FLAGS_MUST_DECRYPT
    header.sec_header.date = int(time())

    # Describe the image to load.
    pimage_length = os.stat(args.inputfile).st_size
    header.sec_header.size_after_decryption = int(pimage_length + bytes_to_alignment(pimage_length, AUTH_HEADER_ALIGN))
    header.sec_header.dummy_clocks_to_write = args.dummy_clocks

    # Reserve space for header checksum:
    checksum_pad_length = bytes_to_alignment(header.size() + 4, AUTH_HEADER_ALIGN)
    checksum_pad = bytearray([0] * checksum_pad_length)
    header.sec_header.offset_to_checksum = header.size() + len(checksum_pad)

    # Additional four bytes is for the header checksum to be calculated:
    image_offset = header.size() + len(checksum_pad) + 4
    
    header.auth_image.type = ALTR_COMMON_AUTH_IMAGE_DECRYPT
    header.auth_image.data.offset = image_offset
    header.auth_image.data.length = encrypted_blob_length

    # Pad the image out to cache line boundary
    image_length = image_offset + encrypted_blob_length
    image_pad_length = bytes_to_alignment(image_length, AUTH_IMAGE_ALIGN)
    image_pad = bytearray([0x00] * image_pad_length)
    
    header.sec_header.load_length = image_length + image_pad_length

    # Finalize the header checksum.
    checksum = simple_checksum(header.to_bytes(), checksum_pad)
    checksum_pad += struct.pack("<L", checksum)

    full_image = header.to_bytes() + checksum_pad + encrypted_blob + image_pad
    full_image_size = len(full_image)
    if full_image_size > ALTR_6XS1_MAX_AUTH_IMAGE_LENGTH:
        raise ValueError('Auth image size too large ({} > {}).'.format(full_image_size, ALTR_6XS1_MAX_AUTH_IMAGE_LENGTH))

    # Write header and encrypted image to file.
    output.write(full_image)
    output.flush()

    delete_tempfiles()
    
    return 0
    
def _disabled(_):
    print ("Encrypt support disabled. No 'quartus_cpf' executable detected!")
    return -1

def register(subparsers):
    info = 'Convert a mkpimage into an encrypted boot image'

    if not find_executable('quartus_cpf'):
        p = subparsers.add_parser('encrypt', help="***DISABLED*** {}".format(info),
                description="***DISABLED*** No 'quartus_cpf' detected!")
        p.set_defaults(operation=_disabled)
    else:
        p = subparsers.add_parser('encrypt', help=info, description=info)
        p.set_defaults(operation=do_encrypt)

    p.add_argument('--inputfile', '-i', required=True,
                   help='Bootloader image to encrypt')
    p.add_argument('--outputfile', '-o', required=True,
                   help='Encrypted output image')
    p.add_argument('--key', '-k', required=True,
                   help='File containing symmetric key to use for encryption')
    p.add_argument('--non-volatile', action='store_true',
                   help='Decryption key stored in non-volatile fuses, instead of battery-backed storage')
    p.add_argument('--dummy-clocks', '-d', default=0, help=argparse.SUPPRESS)
    
