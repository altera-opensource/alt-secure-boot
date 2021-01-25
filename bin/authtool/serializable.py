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

from collections import MutableSequence, MutableMapping
import copy
import itertools
import struct

#import pdb
#pdb.set_trace()

# TODO: should avoid copying buffers to pass to from_bytes()

class Serializable(object):
    def __init__(self, parent=None, name='', **kwargs):
        self.parent = parent
        self.name = name

    def size(self):
        raise NotImplementedError

    def to_bytes(self):
        raise NotImplementedError

    # TODO: change interface to remove 'size' part of tuple, because an instance
    #       may need to be assigned to the parent before it can even calculate
    #       its size (e.g. Padding)
    def from_bytes(self, bytes_in, parent=None, **kwargs):
        raise NotImplementedError

    def offset(self):
        '''
        Calculate byte offset from start of root Serializable to this one
        '''
        if self.parent is None:
            return 0
        else:
            return self.parent.offset() + self.parent.get_field_offset(self)

    # TODO: Move to "container" class that's guaranteed to have _update_hooks
    #       (should also put get_field_offset() there too)
    def notify_field_update(self, field_name):
        for key in list(self._update_hooks.keys()):
            if key.startswith(field_name):
                self._update_hooks[key](self)
                
        if self.parent is not None:
            field_name = "{}.{}".format(self.name, field_name)
            self.parent.notify_field_update(field_name)


class Primitive(Serializable):
    _builtin_type = None
    _format = None
    _size = None
    _constraints = []

    def check_constraints(self):
        return all(constraint(self) for constraint in self._constraints)

    def size(self):
        return self._size

    def to_bytes(self):
        return struct.pack(self._format, self)

    def from_bytes(self, bytes_in, parent=None, **kwargs):
        value = struct.unpack(self._format, bytes_in[0:self._size])[0]
        return type(self)(value, parent=parent, **kwargs), self._size

    def __repr__(self):
        return type(self).__name__ + '(value=0x{:08x})'.format(self)

    def __new__(cls, value=0, **kwargs):
        return cls._builtin_type.__new__(cls, value)
 
    def __init__(self, value=0, **kwargs):
        if not self.check_constraints():
            raise ValueError("Failed constraint check creating {}".format(repr(self)))
        super(Primitive, self).__init__(**kwargs)


# TODO: compute these types instead?
class Byte(Primitive, int):
    _builtin_type = int
    _format = "b"
    _size = struct.calcsize("b")
    _constraints = [lambda s: s.bit_length() <= 8]

class UByte(Primitive, int):
    _builtin_type = int
    _format = "B"
    _size = struct.calcsize("B")
    _constraints = [lambda s: s >= 0,
                    lambda s: s.bit_length() <= 8]


class Int16LE(Primitive, int):
    _builtin_type = int
    _format = "<h"
    _size = struct.calcsize("<h")
    _constraints = [lambda s: s.bit_length() <= 16]

class Int16BE(Primitive, int):
    _builtin_type = int
    _format = ">h"
    _size = struct.calcsize(">h")
    _constraints = [lambda s: s.bit_length() <= 16]

class Int16(Int16BE): pass

class UInt16LE(Primitive, int):
    _builtin_type = int
    _format = "<H"
    _size = struct.calcsize("<H")
    _constraints = [lambda s: s >= 0,
                    lambda s: s.bit_length() <= 16]

class UInt16BE(Primitive, int):
    _builtin_type = int
    _format = ">H"
    _size = struct.calcsize(">H")
    _constraints = [lambda s: s >= 0,
                    lambda s: s.bit_length() <= 16]

class UInt16(UInt16BE): pass


class Int32LE(Primitive, int):
    _builtin_type = int
    _format = "<l"
    _size = struct.calcsize("<l")
    _constraints = [lambda s: s.bit_length() <= 32]

class Int32BE(Primitive, int):
    _builtin_type = int
    _format = ">l"
    _size = struct.calcsize(">l")
    _constraints = [lambda s: s.bit_length() <= 32]

class Int32(Int32BE): pass

class UInt32LE(Primitive, int):
    _builtin_type = int
    _format = "<L"
    _size = struct.calcsize("<L")
    _constraints = [lambda s: s >= 0,
                    lambda s: s.bit_length() <= 32]

class UInt32BE(Primitive, int):
    _builtin_type = int
    _format = ">L"
    _size = struct.calcsize(">L")
    _constraints = [lambda s: s >= 0,
                    lambda s: s.bit_length() <= 32]

class UInt32(UInt32BE): pass

class Int64LE(Primitive, int):
    _builtin_type = int
    _format = "<q"
    _size = struct.calcsize("<q")
    _constraints = [lambda s: s.bit_length() <= 64]

class Int64BE(Primitive, int):
    _builtin_type = int
    _format = ">q"
    _size = struct.calcsize(">q")
    _constraints = [lambda s: s.bit_length() <= 64]

class Int64(Int64BE): pass

class UInt64LE(Primitive, int):
    _builtin_type = int
    _format = "<Q"
    _size = struct.calcsize("<Q")
    _constraints = [lambda s: s >= 0,
                    lambda s: s.bit_length() <= 64]

class UInt64BE(Primitive, int):
    _builtin_type = int
    _format = ">Q"
    _size = struct.calcsize(">Q")
    _constraints = [lambda s: s >= 0,
                    lambda s: s.bit_length() <= 64]

class UInt64(UInt64BE): pass

class Padding(Serializable):
    def __init__(self, pad_to=None, fixed_size=None, fill=0x00, **kwargs):
        if pad_to is None and fixed_size is None:
            raise ValueError("Tried to create Padding with no way to calculate size!")
        self.pad_to = pad_to
        self.fixed_size = fixed_size
        self.fill = fill
        super(Padding, self).__init__(**kwargs)

    def size(self):
        if self.pad_to is None:
            return self.fixed_size
        else:
            offset = self.offset()
            return self.pad_to - (offset % self.pad_to)

    def to_bytes(self):
        return bytearray(self.fill for _ in range(self.size()))

    def from_bytes(self, bytes_in, parent=None, **kwargs):
        # TODO: Preservation of pad byte values -- not especially important?
        instance = type(self)(parent=parent, pad_to=self.pad_to, fixed_size=self.fixed_size, fill=self.fill, **kwargs)
        return instance, instance.size()


class FieldWrapper(object):
    def __init__(self, field_name, default_inst):
        if callable(default_inst):
            default_inst = default_inst()

        if isinstance(default_inst, Serializable):
            default_inst.name = field_name
            self._field_name = field_name
            self._default_inst = default_inst
            self._field_type = type(default_inst)
        else:
            raise TypeError("Tried creating field from non-Serializable!")

    def __get__(self, instance, owner):
        if instance is None:
            return self
        else:
            field = getattr(instance, "_{}".format(self._field_name), None)
            
            if field is None:
                field = copy.deepcopy(self._default_inst)
                field.parent = instance
                setattr(instance, "_{}".format(self._field_name), field)

            return field

    def __set__(self, instance, new_value):
        # TODO: This would be better done with specialized FieldWrapper classes
        # rather than changing behavior conditionally on the field type.
        if isinstance(new_value, self._field_type):
            new_value = copy.deepcopy(new_value)
            new_value.parent = instance
            new_value.name = self._field_name
            setattr(instance, "_{}".format(self._field_name), new_value)
        elif issubclass(self._field_type, Primitive):
            new_value = self._field_type(new_value, parent=instance, name=self._field_name)
            setattr(instance, "_{}".format(self._field_name), new_value)
        elif issubclass(self._field_type, StructureList):
            # TODO: Should coercion into the proper type (so user can assign e.g. [1, 2, 3] rather than [UInt32(1), UInt32(2), UInt32(3)])
            old_list = self.__get__(instance, type(instance))
            bogus_items = [i for i in new_value if not isinstance(i, old_list._struct_type)]
            if not bogus_items:
                new_value = StructureList(new_value, old_list._default_inst, parent=instance, name=self._field_name)
                setattr(instance, "_{}".format(self._field_name), new_value)
            else:
                raise TypeError("Tried inserting StructureList item of {} rather than {}!".format([type(i) for i in bogus_items], self._struct_type))
        else:
            raise TypeError("Tried reassigning field from {} to {}!".format(self._field_type, type(new_value)))

        # TODO: Should prevent basic update hook infinite loops automagically; only 'notify' if field actually changed.
        instance.notify_field_update(self._field_name)


class StructureMeta(type):
    def __init__(self, classname, classbases, classdict):
        for field in getattr(self, '_fields'):
            name, default_inst = field[0], field[1]
            setattr(self, name, FieldWrapper(name, default_inst))

class Structure(Serializable, metaclass= StructureMeta):
    _fields = []
    _update_hooks = dict()

    def each_field(self):
        fields = getattr(self, '_fields')
        for field in fields:
            name, _ = field[0], field[1:]
            yield name, getattr(self, name)

    def size(self):
        return sum(f.size() for n, f in self.each_field())

    def to_bytes(self):
        return bytearray().join(f.to_bytes() for n, f in self.each_field())

    def from_bytes(self, bytes_in, parent=None, depth=0, **kwargs):
        new_instance = type(self)(parent=parent, **kwargs)
        offset = 0
        for field in type(new_instance)._fields:
            name, _ = field[0], field[1]
            field = getattr(new_instance, name)
#            if isinstance(field, (Structure, StructureList)):
#                print "{}0x{:08X}: {:12}".format("  " * depth, offset, name)
            new_field_inst, size = field.from_bytes(bytes_in[offset:], parent=new_instance, depth=(depth+1))
            setattr(new_instance, name, new_field_inst)
            new_field_inst = getattr(new_instance, name)
            size = new_field_inst.size()
#            if isinstance(new_field_inst, Primitive):
#                print "{}0x{:08X} 0x{:08X}: {:12} {}".format("  " * depth, offset, new_instance.get_field_offset(new_field_inst), name, repr(new_field_inst))
#            elif isinstance(new_field_inst, Padding):
#                print "{}0x{:08X} 0x{:08X}: {:12} Padding({})".format("  " * depth, offset, new_instance.get_field_offset(new_field_inst), name, size)
            offset += size

        return new_instance, offset

    def get_field_offset(self, field):
        offset = 0
        for _n, f in self.each_field():
            if f is not field:
                offset += f.size()
            else:
                break
        return offset

    def __init__(self, *args, **kwargs):
        super(Structure, self).__init__(*args, **kwargs)

class StructureList(Serializable, MutableSequence):
    _update_hooks = dict()

    def __init__(self, init_list, default_inst, **kwargs):
        if callable(default_inst):
            default_inst = default_inst()

        self._default_inst = default_inst
        self._struct_type = type(self._default_inst)
        self._list = [copy.deepcopy(item) for item in init_list]
        for item in self._list:
            item.parent = self

        super(StructureList, self).__init__(**kwargs)

    def __getitem__(self, key):
        return self._list[key]
    def __setitem__(self, key, new_value):
        if isinstance(new_value, self._struct_type):
            new_value = copy.deepcopy(new_value)
            new_value.parent = self
            #new_value.name = "[{}]".format(key)
            self._list[key] = new_value
        else:
            raise TypeError("Tried reassigning StructureList item from {} to {}!".format(type(self._list[key]), type(value)))
    def __delitem__(self, key):
        del self._list[key]
        self.length_changed()
    def __len__(self):
        return len(self._list)
    def insert(self, key, new_value):
        if isinstance(new_value, self._struct_type):
            new_value.parent = self
            self._list.insert(key, new_value)
            self.length_changed()
        else:
            raise TypeError("Tried inserting StructureList item of {} rather than {}!".format(type(new_value), self._struct_type))

    def size(self):
        return sum(s.size() for s in self._list)

    def to_bytes(self):
        return bytearray().join(s.to_bytes() for s in self._list)

    def from_bytes(self, bytes_in, parent=None, **kwargs):
        deserialized_list = []
        offset = 0
        for _ in range(len(self)):
            item, size = self._default_inst.from_bytes(bytes_in[offset:])
            deserialized_list.append(item)
            offset += size
        new_instance = type(self)(deserialized_list, self._default_inst, parent=parent, **kwargs)
        return new_instance, offset

    def get_field_offset(self, field):
        fields_before = itertools.takewhile(lambda f: field is not f, self._list)
        return sum(f.size() for f in fields_before)

    def truncate(self, new_length):
        current_length = len(self)
        if current_length == new_length:
            return
        else:
            if new_length < current_length:
                self._list = self._list[:new_length]
            elif new_length > current_length:
                extended_length = new_length - current_length
                self._list.extend([copy.deepcopy(self._default_inst) for _ in range(extended_length)])
            self.length_changed()
        
    def length_changed(self):
        if self.parent is not None:
            self.parent.notify_field_update(self.name)
