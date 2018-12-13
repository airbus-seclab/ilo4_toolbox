import os
from ctypes import *
from struct import pack

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)


class SignatureParams(LittleEndianStructure):

    _fields_ = [
        ("sig_size", c_uint),
        ("modulus", c_byte * 0x200),
        ("exponent", c_byte * 0x200)
    ]

    def to_str(self, byte_array):
        return str(bytearray(byte_array))

    def dump(self):
        print "  > signature size    : 0x%x" % self.sig_size
        print "  > modulus"
        print hexdump(self.to_str(self.modulus))
        print "  > exponent"
        print hexdump(self.to_str(self.exponent))


class BootloaderHeader(LittleEndianStructure):

    _fields_ = [
        ("ilO_magic", c_byte * 4),
        ("build_version", c_char * 0x1C),
        ("type", c_ushort),
        ("compression_type", c_ushort),
        ("field_24", c_uint),
        ("field_28", c_uint),
        ("load_address", c_uint),
        ("total_size", c_uint),
        ("field_34", c_uint),
        ("field_38", c_uint),
        ("field_3C", c_uint),
        ("signature", c_byte * 0x200),
        ("padding", c_byte * 0x200)
    ]

    def to_str(self, byte_array):
        return str(bytearray(byte_array))

    def dump(self):
        print "  > magic              : %s" % self.to_str(self.ilO_magic)
        print "  > build_version      : %s" % self.build_version.split("\x1A")[0]
        print "  > type               : 0x%02x" % self.type
        print "  > compression_type   : 0x%02x" % self.compression_type
        print "  > field_24           : 0x%x" % self.field_24
        print "  > field_28           : 0x%x" % self.field_28
        print "  > load_address       : 0x%x" % self.load_address
        print "  > total_size         : 0x%x" % self.total_size
        print "  > field_34           : 0x%x" % self.field_34
        print "  > field_38           : 0x%x" % self.field_38
        print "  > field_3C           : 0x%x" % self.field_3C
        print "  > signature"
        print hexdump(self.to_str(self.signature))


class BootloaderFooter(LittleEndianStructure):

    _fields_ = [
        ("build_version", c_char * 0x1C),
        ("field_20", c_uint),
        ("field_24", c_uint),
        ("kernel_offset", c_uint),
        ("field_2C", c_uint),
        ("field_30", c_uint),
        ("field_34", c_uint),
        ("field_38", c_uint),
        ("sig_offset", c_uint),
        ("ilO_magic", c_byte * 4),
    ]

    def to_str(self, byte_array):
        return str(bytearray(byte_array))

    def dump(self):
        print "  > magic               : %s" % self.to_str(self.ilO_magic)
        print "  > build_version       : %s" % self.build_version.split("\x1A")[0]
        print "  > field_20            : 0x%x" % self.field_20
        print "  > field_24            : 0x%x" % self.field_24
        print "  > kernel offset       : 0x%x" % self.kernel_offset
        print "  > field_2C            : 0x%x" % self.field_2C
        print "  > field_30            : 0x%x" % self.field_30
        print "  > field_34            : 0x%x" % self.field_34
        print "  > field_38            : 0x%x" % self.field_38
        print "  > sig params offset   : 0x%x" % ((~self.sig_offset + 1) & 0xFFFF)


class ImgHeader(LittleEndianStructure):

    _fields_ = [
        ("ilO_magic", c_byte * 4),
        ("build_version", c_char * 0x1C),
        ("type", c_ushort),
        ("compression_type", c_ushort),
        ("field_24", c_uint),
        ("field_28", c_uint),
        ("decompressed_size", c_uint),
        ("raw_size", c_uint),
        ("load_address", c_uint),
        ("field_38", c_uint),
        ("field_3C", c_uint),
        ("signature", c_byte * 0x200),
        ("padding", c_byte * 0x200)
    ]

    def to_str(self, byte_array):
        return str(bytearray(byte_array))

    def dump(self):
        print "  > magic              : %s" % self.to_str(self.ilO_magic)
        print "  > build_version      : %s" % self.build_version.split("\x1A")[0]
        print "  > type               : 0x%02x" % self.type
        print "  > compression_type   : 0x%02x" % self.compression_type
        print "  > field_24           : 0x%x" % self.field_24
        print "  > field_28           : 0x%x" % self.field_28
        print "  > decompressed_size  : 0x%x" % self.decompressed_size
        print "  > raw_size           : 0x%x" % self.raw_size
        print "  > load_address       : 0x%x" % self.load_address
        print "  > field_38           : 0x%x" % self.field_38
        print "  > field_3C           : 0x%x" % self.field_3C
        print "  > signature"
        print hexdump(self.to_str(self.signature))


# decompress extracted images
def decompress_all(data,fname,chunks=0x10000):
    global window,wchar

    window=['\0']*0x1000
    wchar = 0

    fff = open(fname, "wb")

    while len(data)>0:
        ret = decompress(data[:chunks],fff)
        if len(data) < chunks:
            if ret == 0:
                data = ""
            else:
                data = data[-ret:]
            ret = decompress(data[:chunks],fff,limit=0)
            if ret == 0:
                data = ""
            else:
                data = data[-ret:]
        else:
            data = data[chunks-ret:]

    fff.close()
    return os.path.getsize(fname)


def decompress(data, fff, limit=16):
    global window,wchar
    out=""

    while len(data)>limit:
        comp=ord(data[0])
        data=data[1:]

        for i in xrange(8):
            if limit == 0:
                if len(data) == 0:
                    break
            if ((comp>>(7-i))&0x1) == 1:
                out += data[0]
                window[wchar] = data[0]
                wchar = (wchar+1)%0x1000
                data = data[1:]
            else:
                x = (ord(data[0])>>4)+3
                ptr = wchar - (ord(data[1]) + ((ord(data[0])&0xf)<<8)) - 1
                for k in xrange(x):
                    out += window[(ptr+k)&0xfff]
                    window[wchar] = window[(ptr+k)&0xfff]
                    wchar = (wchar+1)%0x1000
                data = data[2:]

    fff.write(out)
    return len(data)


def compress(data):
    data = ("\x00"*0x1000) + data
    current_off = 0x1000
    oc = 0
    outbuff = ""
    tmp_buff = ""
    mark = 0
    while current_off < len(data):
        k = 3
        off = -1

        while data[current_off:current_off+k] in data[current_off-0x1000:current_off+k-1] and k<19 and (current_off + k) < len(data):
            k += 1

        k -= 1

        if k >= 3:
            off = data[current_off-0x1000:current_off+k-1].rfind(data[current_off:current_off+k])
            if off == 4095 and data[current_off:current_off+k] == data[current_off-0x1000+off-1:current_off-0x1000+off-1+k]:
                off -= 1

        if off == -1:
            mark |= (1<<(7-oc))
            tmp_buff += data[current_off]
            current_off += 1
        else:
            special = (((k-3)<<12) | ((-off-1)&0xfff)) &0xffff
            tmp_buff += pack(">H", special)
            current_off += k
        oc += 1

        if oc == 8:
            outbuff += chr(mark) + tmp_buff
            tmp_buff = ""
            oc = 0
            mark = 0

    while oc < 8:
        mark |= (1<<(7-oc))
        oc += 1
    outbuff += chr(mark) + tmp_buff

    return outbuff
