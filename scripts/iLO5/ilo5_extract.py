#!/usr/bin/python

# Extract binaries from HPIMAGE update file
# Blackbox analysis, might be inaccurate

import os
import sys
from struct import unpack_from, pack
from ctypes import *


BEGIN_SIGN = "--=</Begin HP Signed File Fingerprint\>=--\n"
END_SIGN = "--=</End HP Signed File Fingerprint\>=--\n"
BEGIN_CERT = "-----BEGIN CERTIFICATE-----\n"
END_CERT = "-----END CERTIFICATE-----\n"

window=['\0']*0x1000
wchar = 0

def decompress_all(data,fname,chunks=0x10000):
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


class BootstrapHeader(LittleEndianStructure):

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
        print "  > img_magic              : %s" % self.to_str(self.img_magic)
        print "  > version major      : 0x%x" % self.major
        print "  > version minor      : 0x%x" % self.minor
        print "  > field_A            : 0x%02x" % self.field_A
        print "  > device id          :"
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


class BootstrapFooter(LittleEndianStructure):

    _fields_ = [
        ("module", c_char * 0x20),
        ("fw_magic", c_uint),
        ("field_24", c_uint),
        ("field_28", c_uint),
        ("field_2C", c_uint),
        ("field_30", c_uint),
        ("field_34", c_uint),
        ("field_38", c_uint),
        ("field_3C", c_uint),
        ("field_40", c_uint),
        ("field_44", c_uint),
        ("field_48", c_uint),
        ("field_4C", c_uint),
        ("field_50", c_uint),
        ("field_54", c_uint),
        ("field_58", c_uint),
        ("field_5C", c_uint),
        ("field_60", c_uint),
        ("field_64", c_uint),
        ("field_68", c_uint),
        ("field_6C", c_uint),
        ("field_70", c_uint),
        ("field_74", c_uint),
        ("field_78", c_uint),
        ("field_7C", c_uint),
        ("copyright", c_char * 0x80),
        ("signature", c_byte * 0x200),
        ("gap", c_byte * 0x4FC),
        ("fw_magic_end", c_uint),
    ]

    def to_str(self, byte_array):
        return str(bytearray(byte_array))

    def dump(self):
        print "  > module              : %s" % self.to_str(self.module)
        print "  > fw_magic            : 0x%x" % self.fw_magic
        print "  > field_24            : 0x%x" % self.field_24
        print "  > field_28            : 0x%x" % self.field_28
        print "  > field_2C            : 0x%x" % self.field_2C
        print "  > field_30            : 0x%x" % self.field_30
        print "  > field_34            : 0x%x" % self.field_34
        print "  > field_38            : 0x%x" % self.field_38
        print "  > field_3C            : 0x%x" % self.field_3C
        print "  > field_40            : 0x%x" % self.field_40
        print "  > field_44            : 0x%x" % self.field_44
        print "  > field_48            : 0x%x" % self.field_48
        print "  > field_4C            : 0x%x" % self.field_4C
        print "  > field_50            : 0x%x" % self.field_50
        print "  > field_54            : 0x%x" % self.field_54
        print "  > field_58            : 0x%x" % self.field_58
        print "  > field_5C            : 0x%x" % self.field_5C
        print "  > field_60            : 0x%x" % self.field_60
        print "  > field_64            : 0x%x" % self.field_64
        print "  > field_68            : 0x%x" % self.field_68
        print "  > field_6C            : 0x%x" % self.field_6C
        print "  > field_70            : 0x%x" % self.field_70
        print "  > field_74            : 0x%x" % self.field_74
        print "  > field_78            : 0x%x" % self.field_78
        print "  > field_7C            : 0x%x" % self.field_7C
        print "  > copyright           : %s" % self.to_str(self.copyright)
        print "  > signature"
        print hexdump(self.to_str(self.signature))
        print "  > fw_magic_end       : 0x%x" % self.fw_magic_end


class ImageHeader(LittleEndianStructure):

    _fields_ = [
        ("module", c_char * 0x20),
        ("fw_magic", c_uint),
        ("type", c_uint),
        ("field_28", c_uint),
        ("field_2C", c_uint),
        ("is_compressed", c_uint),
        ("field_34", c_uint),
        ("field_38", c_uint),
        ("field_3C", c_uint),
        ("field_40", c_uint),
        ("decompressed_checksum", c_uint),
        ("compressed_size", c_uint),
        ("decompressed_size", c_uint),
        ("field_50", c_uint),
        ("field_54", c_uint),
        ("field_58", c_short),
        ("field_5A", c_short),
        ("compressed_checksum", c_uint),
        ("field_60", c_uint),
        ("field_64", c_uint),
        ("field_68", c_uint),
        ("field_6C", c_uint),
        ("field_70", c_uint),
        ("field_74", c_uint),
        ("field_78", c_uint),
        ("field_7C", c_uint),
        ("copyright", c_char * 0x80),
        ("signature", c_byte * 0x200),
        ("gap", c_byte * 0x4FC),
        ("fw_magic_end", c_uint),
    ]

    def to_str(self, byte_array):
        return str(bytearray(byte_array))

    def dump(self):
        print "  > module                  : %s" % self.to_str(self.module)
        print "  > fw_magic                : 0x%x" % self.fw_magic
        print "  > type                    : 0x%x" % self.type
        print "  > field_28                : 0x%x" % self.field_28
        print "  > field_2C                : 0x%x" % self.field_2C
        print "  > field_2C                : 0x%x" % self.field_2C
        print "  > is_compressed           : 0x%x" % self.is_compressed
        print "  > field_34                : 0x%x" % self.field_34
        print "  > field_38                : 0x%x" % self.field_38
        print "  > field_3C                : 0x%x" % self.field_3C
        print "  > field_40                : 0x%x" % self.field_40
        print "  > decompressed_checksum   : 0x%x" % self.decompressed_checksum
        print "  > compressed_size         : 0x%x" % self.compressed_size
        print "  > decompressed_size       : 0x%x" % self.decompressed_size
        print "  > field_50                : 0x%x" % self.field_50
        print "  > field_54                : 0x%x" % self.field_54
        print "  > field_58                : 0x%x" % self.field_58
        print "  > field_5A                : 0x%x" % self.field_5A
        print "  > compressed_checksum     : 0x%x" % self.compressed_checksum
        print "  > field_60                : 0x%x" % self.field_60
        print "  > field_64                : 0x%x" % self.field_64
        print "  > field_68                : 0x%x" % self.field_68
        print "  > field_6C                : 0x%x" % self.field_6C
        print "  > field_70                : 0x%x" % self.field_70
        print "  > field_74                : 0x%x" % self.field_74
        print "  > field_78                : 0x%x" % self.field_78
        print "  > field_7C                : 0x%x" % self.field_7C
        print "  > copyright               : %s" % self.to_str(self.copyright)
        print "  > signature"
        print hexdump(self.to_str(self.signature))
        print "  > fw_magic_end       : 0x%x" % self.fw_magic_end


filename = sys.argv[1]
outdir = sys.argv[2]

if len(sys.argv) != 3:
    print "usage: %s <filename> <outdir>"
    sys.exit(1)

if not os.path.exists(outdir):
    os.makedirs(outdir)

with open(filename,"rb") as fff:
    data = fff.read()


#------------------------------------------------------------------------------
# extract certificates

if data.startswith(BEGIN_SIGN):

    off=data.find(END_SIGN)
    # discard for now
    data = data[off+len(END_SIGN):]

    cert_num = 0
    while data.startswith(BEGIN_CERT):
        off=data.find(END_CERT)
        cert_data = data[:off+len(END_CERT)]
        data = data[off+len(END_CERT):]
        print "[+] Extracting certificate %d" % cert_num
        with open(outdir + "/cert%d.x509" % cert_num, "wb") as fff:
            fff.write(cert_data)
        cert_num += 1


#------------------------------------------------------------------------------
# extract HP images: userland, kernel and bootloader

if not data.startswith("HPIMAGE"):
    print "[-] Bad file format"
    sys.exit(1)

hpimage_header = data[:0x4A0]
data = data[0x4A0:]


print "[+]  iLO Bootstrap header :"

with open(outdir + "/hpimage.hdr", "wb") as fff:
    fff.write(hpimage_header)

img_hdr = BootstrapHeader.from_buffer_copy(hpimage_header)
img_hdr.dump()


ilo_bootstrap_footer = data[-0x800:]

print "\n\n"
print "[+] iLO Bootstrap footer 0:"

bootstrap_footer0 = ImageHeader.from_buffer_copy(ilo_bootstrap_footer)
bootstrap_footer0.dump()

with open(outdir + "/bootstrap0.hdr", "wb") as fff:
    fff.write(ilo_bootstrap_footer)


ilo_bootstrap_footer = data[-(bootstrap_footer0.field_3C + 0x800):]

print "\n\n"
print "[+] iLO Bootstrap footer 1:"

bootstrap_footer1 = ImageHeader.from_buffer_copy(ilo_bootstrap_footer)
bootstrap_footer1.dump()

with open(outdir + "/bootstrap1.hdr", "wb") as fff:
    fff.write(ilo_bootstrap_footer[:0x800])

# really not sure about this
bootstrap_offset_start = bootstrap_footer0.field_3C *2
bootstrap_offset_end = bootstrap_footer0.field_3C *2 - bootstrap_footer1.compressed_size

bootstrap = data[-bootstrap_offset_start: -bootstrap_offset_end]
with open(outdir + "/bootstrap.bin", "wb") as fff:
    fff.write(bootstrap)


data = data[:-bootstrap_offset_start]

#------------------------------------------------------------------------------
# extract target info

targetListsize = unpack_from("<L", data)[0]

print "\n\n"
print "[+] iLO target list: %x element(s)" % (targetListsize)

data = data[4:]

for i in range(targetListsize):
    print "    target 0x%x" % i
    print hexdump(data[:0x10])
    data = data[0x10:]

data = data[4:]



#------------------------------------------------------------------------------
# extract modules


ilo_num = 0
mod_list = []

while True:
    print "\n-------------------------------------------------------------------------------"
    print "[+] iLO Header %d" % (ilo_num)

    ilo_header = data[:0x800]
    data = data[0x800:]

    with open(outdir + "/ilo%d.hdr" % ilo_num, "wb") as fff:
        fff.write(ilo_header)

    img_header = ImageHeader.from_buffer_copy(ilo_header)
    img_header.dump()

    mod_list.append(img_header)

    with open(outdir + "/ilo%d.sig" % ilo_num, "wb") as fff:
        fff.write(img_header.to_str(img_header.signature))

    module = data[:img_header.compressed_size]
    with open(outdir + "/ilo%d.raw" % ilo_num, "wb") as fff:
        fff.write(module)

    if img_header.is_compressed == 9:
        output_size = decompress_all(module, outdir + "/ilo%d.bin" % ilo_num)
        print "output_size : 0x%08x\n" % (output_size)

        print "[+] Extracted ilo%d.bin" % ilo_num

    # skip padding bytes
    data = data[img_header.compressed_size:]
    mod_sig = pack("<L", img_header.fw_magic)
    sig_offset  = data.find(mod_sig)

    print "\n>> skip 0x%x" % sig_offset

    if sig_offset == -1:
        print "[x] failed to find next module"
        break

    skip_bytes = sig_offset - 0x20
    data = data[skip_bytes:]
    print "\n>> skip 0x%x" % skip_bytes

    ilo_num +=1



print "\n-------------------------------------------------------------------------------"
print "[+] Modules summary (%d)" % (ilo_num+1)

for i, mod in enumerate(mod_list):
    print "    %2x) %30s  , at 0x%08x" % (i, mod.module, mod.field_28)
