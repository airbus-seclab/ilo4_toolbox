#!/usr/bin/python

# Extract binaries from HPIMAGE update file
# Blackbox analysis, might be inaccurate

import os
import sys
import json
from ilo4lib import *
from struct import unpack_from
from collections import OrderedDict


BEGIN_SIGN = "--=</Begin HP Signed File Fingerprint\>=--\n"
END_SIGN = "--=</End HP Signed File Fingerprint\>=--\n"
BEGIN_CERT = "-----BEGIN CERTIFICATE-----\n"
END_CERT = "-----END CERTIFICATE-----\n"

IMG_LIST = ["elf", "kernel_main", "kernel_recovery"]

HPIMAGE_HDR_SIZE = 0x4B8
BOOTLOADER_HDR_SIZE = 0x440
IMG_HDR_SIZE = 0x440


if len(sys.argv) != 3:
    print "usage: %s <filename> <outdir>"
    sys.exit(1)

filename = sys.argv[1]
outdir = sys.argv[2]

if not os.path.exists(outdir):
    os.makedirs(outdir)

with open(filename,"rb") as fff:
    data = fff.read()

offsets_map = OrderedDict()
global_offset = 0

#------------------------------------------------------------------------------
# extract certificates

if not data.startswith(BEGIN_SIGN):
    print "[-] Bad file format\n    No \"%s\" signature" % BEGIN_SIGN.rstrip()
    sys.exit(1)

off=data.find(END_SIGN)+len(END_SIGN)

# discard for now
data = data[off:]
offsets_map["HP_SIGNED_FILE"] = 0
global_offset = off

cert_num = 0
while data.startswith(BEGIN_CERT):
    off=data.find(END_CERT)+len(END_CERT)
    cert_data = data[:off]
    data = data[off:]
    offsets_map["HP_CERT%d" % cert_num] = global_offset
    global_offset += off
    print "[+] Extracting certificate %d" % cert_num
    with open(outdir + "/cert%d.x509" % cert_num, "wb") as fff:
        fff.write(cert_data)
    cert_num += 1


#------------------------------------------------------------------------------
# extract HP images: userland, kernel and bootloader

if not data.startswith("HPIMAGE"):
    print "[-] Bad file format\n    HPIMAGE magic not found"
    sys.exit(1)

hpimage_header = data[:HPIMAGE_HDR_SIZE]

data = data[HPIMAGE_HDR_SIZE:]
offsets_map["HPIMAGE_HDR"] = global_offset
global_offset += HPIMAGE_HDR_SIZE

with open(outdir + "/hpimage.hdr", "wb") as fff:
    fff.write(hpimage_header)

guid = hpimage_header[0xc:0x1c]

if not data.startswith("iLO3") and not data.startswith("iLO4"):
    print "[-] Bad file format"
    sys.exit(1)

# get signature: should be ilO3 or ilO4
ilo_sign = data[:4]
ilo_bootloader_header = data[:BOOTLOADER_HDR_SIZE]
ilo_bootloader_footer = data[-0x40:]

data = data[BOOTLOADER_HDR_SIZE:]
offsets_map["BOOTLOADER_HDR"] = global_offset
global_offset += BOOTLOADER_HDR_SIZE

print "[+] iLO bootloader header : %s" % (ilo_bootloader_header[:0x1a])

with open(outdir + "/bootloader.hdr", "wb") as fff:
    fff.write(ilo_bootloader_header)

bootloader_header = BootloaderHeader.from_buffer_copy(ilo_bootloader_header)
bootloader_header.dump()

with open(outdir + "/bootloader.sig", "wb") as fff:
    fff.write(bootloader_header.to_str(bootloader_header.signature))

#------------------------------------------------------------------------------
# extract Bootloader footer and cryptographic parameters

print "[+] iLO Bootloader footer : %s" % (ilo_bootloader_footer[:0x1a])

bootloader_footer = BootloaderFooter.from_buffer_copy(ilo_bootloader_footer)
bootloader_footer.dump()

total_size = bootloader_header.total_size

print "\ntotal size:    0x%08x" % total_size
print "payload size:  0x%08x" % len(data)
print "kernel offset: 0x%08x\n" % bootloader_footer.kernel_offset

offsets_map["BOOTLOADER"] = global_offset + total_size -bootloader_footer.kernel_offset - BOOTLOADER_HDR_SIZE
ilo_bootloader = data[-bootloader_footer.kernel_offset:-BOOTLOADER_HDR_SIZE]

with open(outdir + "/bootloader.bin", "wb") as fff:
    fff.write(ilo_bootloader)

data = data[:total_size-BOOTLOADER_HDR_SIZE]

ilo_crypto_params = data[ len(data)-((~bootloader_footer.sig_offset + 1) & 0xFFFF): len(data)-0x40]

with open(outdir + "/sign_params.raw", "wb") as fff:
    fff.write(ilo_crypto_params)

crypto_params = SignatureParams.from_buffer_copy(ilo_crypto_params)
crypto_params.dump()


#------------------------------------------------------------------------------
# extract images

ilo_num=0

off = data.find(ilo_sign)

while off >= 0:

    # skip padding
    if data[:off] != "\xff" * off:
        with open(outdir + "/failed_assert.bin", "wb") as fff:
            fff.write(data)

    assert(data[:off] == "\xff" * off)
    data = data[off:]
    global_offset += off

    # extract header
    ilo_header = data[:IMG_HDR_SIZE]
    data = data[IMG_HDR_SIZE:]

    with open(outdir + "/%s.hdr"% IMG_LIST[ilo_num], "wb") as fff:
        fff.write(ilo_header)

    print "[+] iLO Header %d: %s" % (ilo_num,ilo_header[:0x1a])

    img_header = ImgHeader.from_buffer_copy(ilo_header)
    img_header.dump()

    with open(outdir + "/%s.sig" % IMG_LIST[ilo_num], "wb") as fff:
        fff.write(img_header.to_str(img_header.signature))

    payload_size = img_header.raw_size - IMG_HDR_SIZE

    data1 = data[:payload_size]
    data = data[payload_size:]

    # insert img into offsets map
    offsets_map["%s_HDR" % IMG_LIST[ilo_num].upper()] = global_offset
    global_offset += IMG_HDR_SIZE
    offsets_map["%s" % IMG_LIST[ilo_num].upper()] = global_offset
    global_offset += payload_size

    psz, = unpack_from("<L",data1)
    data1 = data1[4:]
    assert(psz == payload_size-4)
    assert(psz == len(data1))

    window=['\0']*0x1000
    wchar = 0

    with open(outdir + "/%s.raw" % IMG_LIST[ilo_num], "wb") as fff:
        fff.write(data1)

    print "[+] Decompressing"

    output_size = decompress_all(data1,outdir + "/%s.bin" % IMG_LIST[ilo_num])
    print "    decompressed size : 0x%08x\n" % (output_size)

    print "[+] Extracted %s.bin" % IMG_LIST[ilo_num]

    off = data.find(ilo_sign)

    ilo_num += 1
    if ilo_num == 3:
        break


#------------------------------------------------------------------------------
# output offsets map

print "[+] Firmware offset map"
for part, offset in offsets_map.iteritems():
    print "  > %20s at 0x%08x" % (part, offset)

with open(outdir + "/firmware.map", "wb") as fff:
    fff.write(json.dumps(offsets_map, sort_keys=True, indent=4, separators=(',', ': ')))

print "\n> done\n"
