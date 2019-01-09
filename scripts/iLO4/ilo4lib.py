import os
from ctypes import *
from struct import pack
import uuid


DEVICES = {
    uuid.UUID("9d7b312fe3c9764dbff6b9d0d085a952"): "ILO",
    uuid.UUID("2e8d14aa096e3e45bc6f63baa5f5ccc4"): "SYSTEM_ROM",
    uuid.UUID("916b239911c283429ca97423f25687f3"): "CUSTOM_ROM",
    uuid.UUID("9a43adb1d19dc141a4962da9313f1f07"): "CPLD",
    uuid.UUID("3bad180a84cb0c479050cafb33371a14"): "CARBONDALE",
    uuid.UUID("8aa2489e6c5819458405a04f84e27f0f"): "PIC",
    uuid.UUID("90aa533689703a45899c792827a50d67"): "NVME_BP_PIC",
    uuid.UUID("7760b86b75021446aae186618e8b1c27"): "POWER_SUPPLY",
    uuid.UUID("dffc32e2cbbc5347a99bf6b11c6eb074"): "EEPROM_I2C",
    uuid.UUID("18077fda4c441c49b9bfb5a9ccc5e6e8"): "FILES",
    uuid.UUID("0c4c1027c53a91498afbd1f3cd166fb4"): "LANGUAGE_PACK",
    uuid.UUID("a8d1685fab9795408c68bc3e1125268b"): "ILO_MOONSHOT",
    uuid.UUID("8384790bfcabcc4c914e26c4fb948cff"): "CPLD_MOONSHOT"
}

TARGETS = {
    uuid.UUID("2932ecaecc69d843bd0e61dc3406f71b"): "ILO_4",
    uuid.UUID("0000000000000000000000000000ffff"): "SERVER_ID",
    uuid.UUID("00000000000000000000000001FFFFFF"): "BIOS",
    uuid.UUID("00000000000000000000000001ffffff"): "BOOTBLOCK_0",
    uuid.UUID("00000000000000000000000001ffffff"): "BOOTBLOCK 1",
    uuid.UUID("0000000000000000000000000000cdff"): "CARBONDALE 1",
    uuid.UUID("00000000000000000000000000504dff"): "POWER PIC",
    uuid.UUID("000000000000000000000000ffffffff"): "NMVE_BP_PIC",
    uuid.UUID("4cb0f50e84b9984295f04b3fffffffff"): "OEM_DATA",
    uuid.UUID("ffffffffffff000000000cf38db966ea"): "PS1",
    uuid.UUID("ffffffffffff000000000cf38db966ea"): "PS2"
}


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


class HpImageHeader(LittleEndianStructure):

    _fields_ = [
        ("img_magic", c_char * 0x8),
        ("major", c_byte),
        ("minor", c_byte),
        ("field_A", c_ushort),
        ("device_id", c_byte * 0x10),
        ("field_1C", c_uint),
        ("field_20", c_uint),
        ("field_24", c_uint),
        ("field_28", c_uint),
        ("field_2C", c_uint),
        ("field_30", c_uint),
        ("field_34", c_uint),
        ("field_38", c_uint),
        ("field_3C", c_uint),
        ("version", c_char * 0x20),
        ("name", c_char * 0x40),
        ("gap", c_byte * 0x400),
    ]

    def to_str(self, byte_array):
        return str(bytearray(byte_array))

    def dump(self):
        print "  > img_magic          : %s" % self.to_str(self.img_magic)
        print "  > version major      : 0x%x" % self.major
        print "  > version minor      : 0x%x" % self.minor
        print "  > field_A            : 0x%02x" % self.field_A

        dev = ""
        dev_id = uuid.UUID(self.to_str(self.device_id).encode("hex"))
        if dev_id in DEVICES:
            dev = DEVICES[dev_id]

        print "  > device id          : %s" % dev
        print hexdump(self.to_str(self.device_id))
        print "  > field_1C            : 0x%x" % self.field_1C
        print "  > field_20            : 0x%x" % self.field_20
        print "  > field_24            : 0x%x" % self.field_24
        print "  > field_28            : 0x%x" % self.field_28
        print "  > field_2C            : 0x%x" % self.field_2C
        print "  > field_30            : 0x%x" % self.field_30
        print "  > field_34            : 0x%x" % self.field_34
        print "  > field_38            : 0x%x" % self.field_38
        print "  > field_3C            : 0x%x" % self.field_3C
        print "  > version             : %s" % self.to_str(self.version)
        print "  > name                : %s" % self.to_str(self.name)
        print "  > gap"


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
        print "  > build_version      : %s" % self.build_version.split("\x1A")[0].strip()
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
        print "  > build_version       : %s" % self.build_version.split("\x1A")[0].strip()
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
        print "  > build_version      : %s" % self.build_version.split("\x1A")[0].strip()
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
def decompress_all(data, fname, chunks=0x10000):
    global window, wchar

    window = ['\0']*0x1000
    wchar = 0

    fff = open(fname, "wb")

    while len(data)>0:
        ret = decompress(data[:chunks], fff)
        if len(data) < chunks:
            if ret == 0:
                data = ""
            else:
                data = data[-ret:]
            ret = decompress(data[:chunks], fff, limit=0)
            if ret == 0:
                data = ""
            else:
                data = data[-ret:]
        else:
            data = data[chunks-ret:]

    fff.close()
    return os.path.getsize(fname)


def decompress(data, fff, limit=16):
    global window, wchar
    out = ""

    while len(data)>limit:
        comp = ord(data[0])
        data = data[1:]

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
