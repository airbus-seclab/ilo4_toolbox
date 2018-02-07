#!/usr/bin/python

# Extract binaries from HPIMAGE update file
# Blackbox analysis, might be inaccurate

import os
import sys
from struct import unpack_from
from ctypes import *


BEGIN_SIGN = "--=</Begin HP Signed File Fingerprint\>=--\n"
END_SIGN = "--=</End HP Signed File Fingerprint\>=--\n"
BEGIN_CERT = "-----BEGIN CERTIFICATE-----\n"
END_CERT = "-----END CERTIFICATE-----\n"


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


class BootstrapFooter(LittleEndianStructure):

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

if data.startswith("HPIMAGE"):
    hpimage_header = data[:0x4b8]
    data = data[0x4b8:]

    with open(outdir + "/hpimage.hdr", "wb") as fff:
        fff.write(hpimage_header)

    guid = hpimage_header[0xc:0x1c]

if not data.startswith("iLO3") and not data.startswith("iLO4"):
    print "[-] Bad file format"
    sys.exit(1)

sss
# get signature: should be ilO3 or ilO4
ilo_sign = data[:4]
ilo_bootstrap_header = data[:0x440]
ilo_bootstrap_footer = data[-0x40:]
data = data[0x440:]

print "[+] iLO Bootstrap header : %s" % (ilo_bootstrap_header[:0x1a])

with open(outdir + "/bootstrap.hdr", "wb") as fff:
    fff.write(ilo_bootstrap_header)

bootstrap_header = BootstrapHeader.from_buffer_copy(ilo_bootstrap_header)
bootstrap_header.dump()


print "[+] iLO Bootstrap footer : %s" % (ilo_bootstrap_footer[:0x1a])

bootstrap_footer = BootstrapFooter.from_buffer_copy(ilo_bootstrap_footer)
bootstrap_footer.dump()

total_size = bootstrap_header.total_size

print "total size:    0x%08x" % total_size
print "payload size: 0x%08x\n" % len(data)
print "kernel offset: 0x%08x\n" % bootstrap_footer.kernel_offset

ilo_bootstrap = data[-bootstrap_footer.kernel_offset:-0x440]

with open(outdir + "/bootstrap.raw", "wb") as fff:
    fff.write(ilo_bootstrap)

data = data[:total_size-0x440]
ilo_header = data[:0x440]
data = data[0x440:]

ilo_crypto_params = data[ len(data)-((~bootstrap_footer.sig_offset + 1) & 0xFFFF): len(data)-0x40]

with open(outdir + "/sign_params.raw", "wb") as fff:
    fff.write(ilo_crypto_params)


crypto_params = SignatureParams.from_buffer_copy(ilo_crypto_params)

crypto_params.dump()


sys.exit()
#------------------------------------------------------------------------------
# extract first header

ilo_num=0

print "[+] iLO Header %d: %s" % (ilo_num,ilo_header[:0x1a])

with open(outdir + "/ilo%d.hdr" % ilo_num, "wb") as fff:
    fff.write(ilo_header)

img_header = ImgHeader.from_buffer_copy(ilo_header)
img_header.dump()

with open(outdir + "/ilo%d.sig" % ilo_num, "wb") as fff:
        fff.write(img_header.to_str(img_header.signature))

payload_size = img_header.raw_size

print "payload_size 0x%08x" % payload_size

data1 = data[:payload_size-0x440]
data = data[payload_size-0x440:]
psz, = unpack_from("<L",data1)
data1 = data1[4:]

assert(psz == payload_size-0x440-4)
assert(psz == len(data1))

# decompress extracted images
window=['\0']*0x1000
wchar = 0

with open(outdir + "/ilo%d.raw" % ilo_num, "wb") as fff:
    fff.write(data1)

output_size = decompress_all(data1,outdir + "/ilo%d.bin" % ilo_num)
print "output_size : 0x%08x\n" % (output_size)

print "[+] Extracted ilo%d.bin" % ilo_num

ilo_num += 1

#------------------------------------------------------------------------------

off = data.find(ilo_sign)

while off > 0:

    if data[:off] != "\xff" * off:
        with open(outdir + "/failed_assert.bin", "wb") as fff:
            fff.write(data)

    assert(data[:off] == "\xff" * off)
    data = data[off:]

    ilo_header = data[:0x440]
    data = data[0x440:]

    with open(outdir + "/ilo%d.hdr"%ilo_num, "wb") as fff:
        fff.write(ilo_header)

    print "[+] iLO Header %d: %s" % (ilo_num,ilo_header[:0x1a])

    img_header = ImgHeader.from_buffer_copy(ilo_header)
    img_header.dump()

    with open(outdir + "/ilo%d.sig" % ilo_num, "wb") as fff:
        fff.write(img_header.to_str(img_header.signature))

    payload_size = img_header.raw_size

    data1 = data[:payload_size-0x440]
    data = data[payload_size-0x440:]
    psz, = unpack_from("<L",data1)
    data1 = data1[4:]

    print "psz 0x%08x\n\n" % psz

    assert(psz == payload_size-0x440-4)
    assert(psz == len(data1))

    window=['\0']*0x1000
    wchar = 0

    with open(outdir + "/ilo%d.raw" % ilo_num, "wb") as fff:
        fff.write(data1)

    output_size = decompress_all(data1,outdir + "/ilo%d.bin" % ilo_num)
    print "decompressed size : 0x%08x\n" % (output_size)

    print "[+] Extracted ilo%d.bin" % ilo_num

    off = data.find(ilo_sign)

    ilo_num += 1
    if ilo_num == 3:
        break

print "> done"
