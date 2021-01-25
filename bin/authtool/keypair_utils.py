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
from subprocess import Popen, PIPE, call
from hashlib import sha256
from itertools import zip_longest
from io import StringIO

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.error import PyAsn1Error
from pyasn1_modules.pem import readPemBlocksFromFile
from pyasn1_modules.rfc5208 import PrivateKeyInfo

from authtool.X9_62 import ECPrivateKey, algo_oid_to_name


def grouper(iterable, n, fillvalue=None):
    """Collect data into fixed-length chunks or blocks"""
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return zip_longest(fillvalue=fillvalue, *args)

def bit_tuple_to_bytes(t):
    return bytearray(group[0] << 7 |
                     group[1] << 6 |
                     group[2] << 5 |
                     group[3] << 4 |
                     group[4] << 3 |
                     group[5] << 2 |
                     group[6] << 1 |
                     group[7] for group in grouper(t, 8, 0))

def _x9_62_extract_pubkey(der_form):
    try:
        ec_private_key = der_decoder.decode(der_form, asn1Spec=ECPrivateKey())[0]

        pubkey = ec_private_key['publicKey']
        if ec_private_key['parameters'] and ec_private_key['parameters']['named_curve']:
            key_algo = ec_private_key['parameters']['named_curve']
        else:
            key_algo = None
        
        return pubkey, key_algo
    except PyAsn1Error as asn1_err:
        return None, None
    
def _pkcs8_extract_pubkey(der_form):
    try:
        pkcs8 = der_decoder.decode(der_form, asn1Spec=PrivateKeyInfo())[0]
        pkcs8_key_algo = der_decoder.decode(pkcs8['privateKeyAlgorithm']['parameters'])[0]
    except PyAsn1Error as asn1_err:
        return None, None

    pubkey, key_algo = _x9_62_extract_pubkey(pkcs8['privateKey'])

    if key_algo is None:
        # Try to fall back to a PKCS8-extracted value:
        key_algo = pkcs8_key_algo
    
    return pubkey, key_algo

def _is_bootrom_supported_raw_ecc_pubkey(pubkey):
    # The first byte of public key indicates the elliptic curve point's form.
    # Since the BootROM supports only the uncompressed (4) or hybrid (6, 7)
    # forms, sanity check the key for this value.
    return pubkey[0] not in [4, 6, 7]

def keypair_extract_raw_pubkey(keypair):
    """Extract a public key and its algorithm from a keypair.

    Input may be a string or file object, with keypair represented in either
    PKCS8-wrapped or X9.62 format (but only PEM encoded for now -- no DER).
    """
    if isinstance(keypair, str):
        keypair = StringIO(keypair)

    _, der_string = readPemBlocksFromFile(
                        keypair,
                        ('-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----'),
                        ('-----BEGIN EC PRIVATE KEY-----', '-----END EC PRIVATE KEY-----'))

    pubkey, key_algo = _pkcs8_extract_pubkey(der_string)

    if pubkey is None:
        pubkey, key_algo = _x9_62_extract_pubkey(der_string)

    if pubkey is not None and not _is_bootrom_supported_raw_ecc_pubkey(pubkey):
        pubkey = None
    
    if pubkey is not None and key_algo is not None:
        return bit_tuple_to_bytes(pubkey), algo_oid_to_name(key_algo)
    else:
        return None, None

def sign_data(signing_key, data, openssl='openssl'):
    cmd = [openssl, 'pkeyutl', '-sign', '-inkey', signing_key]

    try:
        message_digest = sha256(data).digest()
        signature = None
    
        # data to sign (i.e. the message digest) ==> openssl ==> signature
        openssl = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        stdout, stderr = openssl.communicate(message_digest)

        if openssl.returncode == 0:
            signature = stdout
    except OSError:
        print("Unable to execute openssl command: {}".format(" ".join(cmd)))

    return signature

def is_valid_signature(validation_key, data, signature, openssl='openssl'):
    cmd = [openssl, 'pkeyutl', '-verify', '-inkey', validation_key, '-sigfile', signature]

    try:
        message_digest = sha256(data).digest()
        is_valid = None
    
        openssl = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        stdout, stderr = openssl.communicate(message_digest)

        # It would be better to not scrape the output for result, but the
        #   command's return code seems to be '1' either way.
        if stdout.startswith("Signature Verified Successfully"):
            is_valid = True
        else:
            is_valid = False
    except OSError:
         print("Unable to execute openssl command: {}".format(" ".join(cmd)))

    return is_valid

def has_openssl_feature(feature, openssl='openssl'):
    with open(os.devnull, 'wb', 0) as bitbucket:
        cmd = [openssl, 'no-{}'.format(feature)]
        if call(cmd, stdout=bitbucket):
            return True
        else:
            return False
