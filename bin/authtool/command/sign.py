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
import hashlib
import os
import struct
import traceback
from hashlib import sha256
from time import time

from authtool.utils import string_to_tempfile, delete_tempfiles
from authtool.keypair_utils import has_openssl_feature, keypair_extract_raw_pubkey, sign_data
from authtool.authheader import (AuthHeader, AuthSig, is_authheader_image, is_pheader_image, simple_checksum, bytes_to_alignment,
                                 ALTR_6XS1_COMMON_AUTHHEADER_FLAGS_MUST_AUTH,
                                 ALTR_6XS1_MAX_AUTH_IMAGE_LENGTH,
                                 ALTR_COMMON_AUTH_ECC_256,
                                 ALTR_COMMON_AUTH_ECC_384,
                                 ALT_COMMON_AUTH_KEY_TYPE_BOOT,
                                 ALT_COMMON_AUTH_KEY_TYPE_FUSE,
                                 ALT_COMMON_AUTH_KEY_TYPE_LE,
                                 ALT_COMMON_AUTH_KEY_TYPE_USER,
                                 ALT_COMMON_AUTH_MAGIC,
                                 ALT_COMMON_AUTH_VERSION,
                                 AUTH_HEADER_ALIGN)

A10_BOOTROM_KEYPAIR = '''\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6/D3V3vcsxWLfD42
OThd+6RIxWjgChTIYQIPJnXEYnehRANCAASkqLXj/uHhQIpMjW5iXa0Yj2Es62Il
AwHhBa6SDmqAoFt6VHvQ3zrpqtR4Op6AUeDD9BQjzyqvucv095tDoFv7
-----END PRIVATE KEY-----
'''

def do_sign(args):
    try:
        do_sign_process(args)
    except Exception:
        print(traceback.format_exc())

def do_sign_process(args):

    input_image = open(args.inputfile, "rb").read()
    input_image_size = len(input_image)

    if is_pheader_image(input_image):
        header = AuthHeader()
        image = input_image
        image_size = input_image_size
        embedded_keydata = bytearray("", encoding = "utf-8")

    elif is_authheader_image(input_image):
        header, size = AuthHeader().from_bytes(input_image)

        if (header.sec_header.flags
            & ALTR_6XS1_COMMON_AUTHHEADER_FLAGS_MUST_AUTH) != 0:
            raise ValueError("Input image is already signed.")

        auth_image_offset = header.auth_image.data.offset
        auth_image_size = header.auth_image.data.length
        image = input_image[auth_image_offset:(auth_image_offset + auth_image_size)]
        image_size = len(image)

        embedded_keydata = bytearray(input_image[size:auth_image_offset])
        if len(embedded_keydata) > AUTH_HEADER_ALIGN:
            raise ValueError("Unexpected data found in image.")
        # Recalculate pad/checksum because the embedded keys still need to be added
        embedded_keydata = bytearray("", encoding = "utf-8")
    else:
        raise ValueError("Format of input image not recognized.")

    # Set up the trusted root key fields.
    if args.rootkey_type == 'fuse':
        if len(args.keypair) < 1:
            raise ValueError("No signing keypairs provided. Please specify at least one --keypair argument.")

        header.root_key.type = ALT_COMMON_AUTH_KEY_TYPE_FUSE

        root_key, subroot_keys = args.keypair[0], args.keypair[1:]
        header.auth_sig = [AuthSig() for _ in range(len(subroot_keys))]

        pubkey, root_key_algo = keypair_extract_raw_pubkey(open(root_key, 'r'))

        if pubkey is None:
            raise ValueError("Could not extract public key from keypair file '{}'.".format(root_key))

        header.root_key.key.offset = header.size()
        header.root_key.key.length = len(pubkey)
        embedded_keydata += pubkey

    elif args.rootkey_type == 'fpga':
        if len(args.keypair) < 1:
            raise ValueError("No signing keypairs provided. Please specify at least one --keypair argument.")
        elif args.fpga_key_offset is None:
            raise ValueError("Trusted root key of 'fpga' type selected, but --fpga-key-offset has not been provided.")

        header.root_key.type = ALT_COMMON_AUTH_KEY_TYPE_LE

        root_key, subroot_keys = args.keypair[0], args.keypair[1:]
        header.auth_sig = [AuthSig() for _ in range(len(subroot_keys))]

        pubkey, root_key_algo = keypair_extract_raw_pubkey(open(root_key, 'r'))

        if pubkey is None:
            raise ValueError("Could not extract public key from keypair file '{}'.".format(root_key))

        header.root_key.key.offset = int(args.fpga_key_offset)
        header.root_key.key.length = len(pubkey)

    elif args.rootkey_type == 'user':
        if len(args.keypair) < 1:
            raise ValueError("No signing keypairs provided. Please specify at least one --keypair argument.")

        header.root_key.type = ALT_COMMON_AUTH_KEY_TYPE_USER

        root_key, subroot_keys = args.keypair[0], args.keypair[1:]
        header.auth_sig = [AuthSig() for _ in range(len(subroot_keys))]

        pubkey, root_key_algo = keypair_extract_raw_pubkey(open(root_key, 'r'))

        if pubkey is None:
            raise ValueError("Could not extract public key from keypair file '{}'.".format(root_key))

        header.root_key.key.offset = header.size()
        header.root_key.key.length = len(pubkey)
        embedded_keydata += pubkey

    elif args.rootkey_type == 'bootrom':
        # No arg.keypair keys needed; using the BootROM's built-in test key for trusted root keypair.

        header.root_key.type = ALT_COMMON_AUTH_KEY_TYPE_BOOT

        root_key = string_to_tempfile(A10_BOOTROM_KEYPAIR)
        subroot_keys = args.keypair
        header.auth_sig = [AuthSig() for _ in range(len(subroot_keys))]

        header.root_key.key.offset = 0

        pubkey, root_key_algo = keypair_extract_raw_pubkey(open(root_key, 'r'))

    pubkey_hash = sha256(pubkey)
    print("SHA256 digest of root public key: {}".format(pubkey_hash.hexdigest()))

    if args.pubkeyout is not None:
        with open(args.pubkeyout, 'wb') as pko:
            pko.write(pubkey)

    if args.fuseout is not None:
        with open(args.fuseout, 'wb') as fo:
            fo.write(pubkey_hash.digest())

    header.sec_header.magic = ALT_COMMON_AUTH_MAGIC
    header.sec_header.version = ALT_COMMON_AUTH_VERSION
    header.sec_header.flags |= ALTR_6XS1_COMMON_AUTHHEADER_FLAGS_MUST_AUTH
    header.sec_header.date = int(time())

    # Populate subroot keys if any are requested.
    current_signing_key = root_key
    current_signing_algo = root_key_algo
    for key_num, key in enumerate(subroot_keys):
        #print "{} is signing {}".format(current_signing_key, key)
        pubkey, algo = keypair_extract_raw_pubkey(open(key, 'r'))
        signature = sign_data(current_signing_key, pubkey)

        if algo == 'prime256v1':
            header.auth_sig[key_num].type = ALTR_COMMON_AUTH_ECC_256
        elif algo == 'secp384r1':
            header.auth_sig[key_num].type = ALTR_COMMON_AUTH_ECC_384
        else:
            raise ValueError('Unrecognized algorithm type signing subroot_key[{}]'.format(key_num))

        header.auth_sig[key_num].data.offset = header.size() + len(embedded_keydata)
        header.auth_sig[key_num].data.length = len(pubkey)
        embedded_keydata += pubkey

        header.auth_sig[key_num].sig.offset = header.size() + len(embedded_keydata)
        header.auth_sig[key_num].sig.length = len(signature)
        embedded_keydata += signature

        current_signing_key = key
        current_signing_algo = algo

    # Reserve space for header checksum:
    checksum_pad_length = bytes_to_alignment(header.size() + len(embedded_keydata) + 4, AUTH_HEADER_ALIGN)
    embedded_keydata += bytearray([0] * checksum_pad_length)
    header.sec_header.offset_to_checksum = header.size() + len(embedded_keydata)

    # Additional four bytes is for the header checksum word:
    image_offset = header.size() + len(embedded_keydata) + 4

    header.auth_image.data.offset = image_offset
    header.auth_image.data.length = image_size
    # The ECC signature output is not only impure (it utilizes a random input
    # internally), but its length varies as a result of ASN.1 integer encoding.
    # Because the full-image signature necessarily includes its own width in the
    # data to be sign, the script must take a guess at the width and resign the
    # image until values are consistent (loop below with sign_data() call).
    if current_signing_algo == 'prime256v1':
        header.auth_image.sig.length = 71   # Commonly is 70, 71, 72
    elif current_signing_algo == 'secp384r1':
        header.auth_image.sig.length = 103  # Commonly is 102, 103, 104
    else:
        raise ValueError('Unrecognized algorithm type requested for full-image signature')

    # Pad the image length to align to cache boundary:
    auth_image_length = image_offset + image_size + header.auth_image.sig.length
    extra_pad_length = bytes_to_alignment(auth_image_length, AUTH_HEADER_ALIGN)
    extra_pad = bytearray([0x0] * extra_pad_length)
    auth_image_length += extra_pad_length

    header.auth_image.sig.offset = image_offset + image_size + extra_pad_length
    header.sec_header.load_length = auth_image_length

    # Finalize the header checksum.
    checksum = simple_checksum(header.to_bytes(), embedded_keydata)
    embedded_keydata += struct.pack("<L", checksum)

    # Sign the full image.
    image_data = bytearray('', encoding = "utf-8").join([header.to_bytes(),
                                     embedded_keydata,
                                     image,
                                     extra_pad])
    image_signature = bytearray('', encoding = "utf-8")

    for _attempt in range(100):
        image_signature = sign_data(current_signing_key, image_data)
        if len(image_signature) == header.auth_image.sig.length:
            break
    else:
        raise ValueError('Calculated full-image signature 100 times, but its length never matched the pre-decided value of auth_image.sig.length. This is extremely improbable if ECDSA is performed correctly; aborting rather than outputting a suspect image.')

    full_image_size = len(image_data) + len(image_signature)
    if full_image_size > ALTR_6XS1_MAX_AUTH_IMAGE_LENGTH:
        raise ValueError('Auth image size too large ({} > {}).'.format(full_image_size, ALTR_6XS1_MAX_AUTH_IMAGE_LENGTH))
    # Write header, keys, signatures, and image to file.
    output = open(args.outputfile, 'wb')
    output.writelines([image_data, image_signature])
    output.flush()

    delete_tempfiles()

    return 0

def _disabled(_):
    print ("Signing support disabled. No OpenSSL support for 'ec' detected!")
    return -1

def int_allow_hex(string):
    if string.startswith('0x'):
        return int(string, 16)
    else:
        return int(string)

def register(subparsers):
    info = 'Sign a bootloader image to allow BootROM verification'
    handler = do_sign

    if not has_openssl_feature('ec'):
        p = subparsers.add_parser('sign', help="***DISABLED*** {}".format(info),
                description="***DISABLED*** No OpenSSL support for 'ec' detected!")
        p.set_defaults(operation=_disabled)
    else:
        p = subparsers.add_parser('sign', help=info, description=info)
        p.set_defaults(operation=do_sign)

    p.add_argument('--inputfile', '-i', required=True,
                   help='Bootloader image to sign')
    p.add_argument('--outputfile', '-o', required=True,
                   help='Signed output image')
    p.add_argument('--fuseout', '-fo',
                   help='Hash of root public key, to be burned into device fuses')
    p.add_argument('--pubkeyout', '-pko',
                   help='Root public key in raw data form. This data may then be built into the FPGA image for usage with --rootkey-type=fpga')
    p.add_argument('--rootkey-type', '-t', default='fuse', choices=['fuse', 'fpga', 'user'],
                   help="The trusted root key's type. (default: %(default)s)"\
			"  \'fuse\': embed root pubkey in image. BootROM verifies its hash against device fuses. "\
			"  \'fpga\': fetch trusted root pubkey from location in FPGA memory. "\
			"  \'user': embed root pubkey in image. BootROM does not verify.")
    #'fuse' - embed root pubkey in image. BootROM verifies its hash against device fuses
    #'fpga' - fetch trusted root pubkey from location in FPGA memory
    #'user' - embed root pubkey in image. BootROM does not verify -- untrusted boot!
    #'bootrom' - use BootROM's embedded keypair for root key. The private key is published -- untrusted boot!
    p.add_argument('--keypair', '-k', action='append', default=[],
                   help='Signature keypairs specified in order from the trusted root key to final user key')
    p.add_argument('--fpga-key-offset', type=int_allow_hex,
                   help="Offset from H2F bridge base address (0xC0000000) to location of logic-embedded root public key. Used for '--rootkey-type fpga' authentication.")
