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

from pyasn1.type import univ, namedtype, tag

class ECVersion(univ.Integer): pass
class ECPrivateKey(univ.OctetString): pass

# FieldID
class X9_62_FieldID(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('fieldType', univ.ObjectIdentifier()),
        namedtype.NamedType('parameters', univ.Any())
    )

# Curve
class X9_62_Curve(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('a', univ.OctetString()),
        namedtype.NamedType('b', univ.OctetString()),
        namedtype.OptionalNamedType('seed', univ.BitString())
    )

# SpecifiedECDomain
class ECParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('fieldID', X9_62_FieldID()),
        namedtype.NamedType('curve', X9_62_Curve()),
        namedtype.NamedType('base', univ.OctetString()),
        namedtype.NamedType('order', univ.Integer()),
        namedtype.OptionalNamedType('cofactor', univ.Integer())
    )
        
class ECPKParameters(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('named_curve', univ.ObjectIdentifier()),
        namedtype.NamedType('parameters', ECParameters()),
        namedtype.NamedType('implicitlyCA', univ.Null())
    )
    
class ECPublicKey(univ.BitString): pass

class ECPrivateKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', ECVersion()),
        namedtype.NamedType('privateKey', ECPrivateKey()),
        namedtype.OptionalNamedType('parameters', ECPKParameters().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('publicKey', ECPublicKey().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    )


def algo_oid_to_name(algo_oid):
    """Map public key algorithm OID to friendly name string used by OpenSSL."""

    lookup = {
            univ.ObjectIdentifier('1.2.840.10045.3.1.7'): "prime256v1",
            univ.ObjectIdentifier('1.3.132.0.34'): "secp384r1",
        }

    if algo_oid in lookup:
        return lookup[algo_oid]
    else:
        return "unknown"
