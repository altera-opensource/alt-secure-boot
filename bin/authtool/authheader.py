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

import struct
import itertools

from authtool.serializable import Padding, StructureList, Structure, UInt32LE, UInt64LE


ALT_COMMON_AUTH_MAGIC   = 0x74944592
ALT_COMMON_AUTH_VERSION = 0x00000000

ALTR_COMMON_AUTH_TYPE_ECC = 0x00010000
ALTR_COMMON_AUTH_ECC_256 = ALTR_COMMON_AUTH_TYPE_ECC | 256
ALTR_COMMON_AUTH_ECC_384 = ALTR_COMMON_AUTH_TYPE_ECC | 384

ALTR_COMMON_AUTH_IMAGE_DECRYPT = 0x00010000

ALT_COMMON_AUTH_KEY_TYPE_NONE = 0x00000000
ALT_COMMON_AUTH_KEY_TYPE_FUSE = 0x00000001
ALT_COMMON_AUTH_KEY_TYPE_USER = 0x00000002
ALT_COMMON_AUTH_KEY_TYPE_BOOT = 0x00000003
ALT_COMMON_AUTH_KEY_TYPE_LE   = 0x00000004

ALT_COMMON_AUTH_OPTION_TYPE_HPS  = 0x00000001
ALT_COMMON_AUTH_OPTION_TYPE_FPGA = 0x00000002

ALTR_6XS1_COMMON_AUTHHEADER_FLAGS_MUST_DECRYPT = 0x00000001
ALTR_6XS1_COMMON_AUTHHEADER_FLAGS_MUST_AUTH = 0x00000002

ALTR_6XS1_MAX_AUTH_IMAGE_LENGTH = 8 * 1024 * 1024

# mkpimage fingerprint
ALTR_6XS1_PH_MAGIC = 0x31305341

#
# AUTH_HEADER_ALIGN : Alignment needed by header data. Needed for sign and encrypt.
# AUTH_IMAGE_ALIGN  : Alignment needed by image data. Needed for encrypt only.
#
AUTH_HEADER_ALIGN = 0x20
AUTH_IMAGE_ALIGN  = 0x10

class SecHeader(Structure):
    _fields = [
        ("magic",                 UInt32LE),
        ("version",               UInt32LE),
        ("header_length",         UInt32LE),
        ("load_length",           UInt32LE),
        ("number_of_sigs",        UInt32LE),
        ("offset_to_checksum",    UInt32LE),
        ("flags",                 UInt32LE),
        ("size_after_decryption", UInt32LE),
        ("date",                  UInt64LE),
        ("dummy_clocks_to_write", UInt32LE),
        ("spare",                 Padding(pad_to=0x0100)),
        ]

class OptionData(Structure):
    _fields = [
        ("flags",     UInt32LE),
        ("fpga_opt1", UInt32LE),
        ("hps_opt1",  UInt32LE),
        ("hps_opt2",  UInt32LE),
        ("spare",     Padding(pad_to=0x0040)),
        ]

class DataOffset(Structure):
    _fields = [
        ("offset", UInt32LE),
        ("length", UInt32LE),
        ]

class RootKey(Structure):
    _fields = [
        ("type",   UInt32LE),
        ("spare1", Padding(fixed_size=4)),
        ("key",    DataOffset),
        ("spare2", Padding(pad_to=0x0020)),
        ]

class AuthImage(Structure):
    _fields = [
        ("type",  UInt32LE),
        ("data",  DataOffset),
        ("sig",   DataOffset),
        ("spare", Padding(pad_to=0x0020)),
        ]

class AuthSig(Structure):
    _fields = [
        ("data",  DataOffset),
        ("sig",   DataOffset),
        ("type",  UInt32LE),
        ("spare", Padding(pad_to=0x0020)),
        ]

class AuthHeader(Structure):
    # sec_header:
    #  0x0000 magic
    #  0x0004 version
    #  0x0008 header_length
    #  0x000C load_length
    #  0x0010 number_of_sigs
    #  0x0014 offset_to_checksum
    #  0x0018 flags
    #  0x001C size_after_decryption
    #  0x0020 date
    #  0x0028 dummy_clocks_to_write
    #  0x002C..0x0100 reserved
    # option_data:
    #  0x0100 flags
    #  0x0104 fpga_opt1
    #  0x0108 hps_opt1
    #  0x010C hps_opt2
    #  0x0110..0x0140 reserved
    # reserved:
    #  0x0140..0x0200 reserved
    # root_key:
    #  0x0200 type
    #  0x0204 reserved
    #  0x0208 key (DataOffset)
    #  0x0210..0x0220 reserved
    # auth_image:
    #  0x0220 type
    #  0x0224 data (DataOffset)
    #  0x022C sig (DataOffset)
    #  0x0234..0x0240 reserved
    # reserved:
    #  0x0240..0x0400 reserved
    # [if using any subroot keys:]
    # auth_sig_0:
    #  0x0400 data (DataOffset)
    #  0x0408 sig (DataOffset)
    #  0x0410 type
    #  0x0414..0x0420 reserved
    # auth_sig_<n>:
    #  0x0420 data
    #  0x0428 sig
    #  0x0430 type
    #  0x0434..0x0440 reserved
    # ...

    _fields = [
        ("sec_header",  SecHeader),
        ("option_data", OptionData),
        ("spare1",      Padding(pad_to=0x0200)),
        ("root_key",    RootKey),
        ("auth_image",  AuthImage),
        ("spare2",      Padding(pad_to=0x0400)),
        ("auth_sig",    StructureList([], AuthSig)),
        ]

    _update_hooks = {
        'auth_sig':                  lambda s: s.update_num_sigs(),
        'sec_header.number_of_sigs': lambda s: s.update_auth_sig_length(),
        }

    def update_auth_sig_length(self):
        self.auth_sig.truncate(self.sec_header.number_of_sigs)
    def update_num_sigs(self):
        self.sec_header.number_of_sigs = len(self.auth_sig)


def is_pheader_image(bytes_in):
    magic_word = struct.unpack_from("<L", bytes_in, offset=0x40)[0]
    if magic_word == ALTR_6XS1_PH_MAGIC:
        return True
    else:
        return False

def is_authheader_image(bytes_in):
    magic_word = struct.unpack_from("<L", bytes_in, offset=0)[0]
    if magic_word == ALT_COMMON_AUTH_MAGIC:
        return True
    else:
        return False

def simple_checksum(*bytearrays):
    return sum(itertools.chain(*bytearrays)) & 0xffffffff
    
def is_power_of_two(n):
    if n != 0 and (n & (n-1)) == 0:
        return True
    else:
        return False

def bytes_to_alignment(offset, align_to):
    if not is_power_of_two(align_to):
        raise ValueError("Alignment boundary to pad to is not a power-of-two.")

    offset_from_boundary = (align_to - 1) & offset

    if offset_from_boundary != 0:
        return align_to - offset_from_boundary
    else:
        return 0
