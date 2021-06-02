#!/usr/bin/python

# Extract binaries from HPIMAGE update file
# Blackbox analysis, might be inaccurate

import os
import sys
import json
from ilo5lib import *
from struct import unpack_from, pack
from collections import OrderedDict

BEGIN_SIGN = b"--=</Begin HP Signed File Fingerprint\>=--\n"
END_SIGN = b"--=</End HP Signed File Fingerprint\>=--\n"
BEGIN_CERT = b"-----BEGIN CERTIFICATE-----\n"
END_CERT = b"-----END CERTIFICATE-----\n"

IMG_LIST = ["bootloader1_main", "bootloader1_recovery",
            "bootloader2_main", "bootloader2_recovery",
            "kernel_main", "kernel_recovery",
            "elf_stager", "elf_secure", "elf_recovery"]

HPIMAGE_HDR_SIZE = 0x4A0
IMG_HDR_SIZE = 0x800
BOOT_BLOCK_SIZE = 0x10000

filename = sys.argv[1]
outdir = sys.argv[2]

if len(sys.argv) != 3:
    print("usage: %s <filename> <outdir>")
    sys.exit(1)

if not os.path.exists(outdir):
    os.makedirs(outdir)

with open(filename, "rb") as fff:
    data = fff.read()

offsets_map = OrderedDict()
global_offset = 0


#------------------------------------------------------------------------------
# extract certificates

if not data.startswith(BEGIN_SIGN):
    print("[-] Bad file format\n    No \"%s\" signature" % BEGIN_SIGN.rstrip())
    sys.exit(1)

off = data.find(END_SIGN) + len(END_SIGN)

# discard for now
data = data[off:]
offsets_map["HP_SIGNED_FILE"] = 0
global_offset = off

cert_num = 0
while data.startswith(BEGIN_CERT):
    off = data.find(END_CERT) + len(END_CERT)
    cert_data = data[:off]
    data = data[off:]
    offsets_map["HP_CERT%d" % cert_num] = global_offset
    global_offset += off
    print("[+] Extracting certificate %d" % cert_num)
    with open(outdir + "/cert%d.x509" % cert_num, "wb") as fff:
        fff.write(cert_data)
    cert_num += 1

#------------------------------------------------------------------------------
# extract HP images: userland, kernel and bootloader

mod_list = []

if not data.startswith(b"HPIMAGE"):
    print("[-] Bad file format")
    sys.exit(1)

hpimage_header = data[:HPIMAGE_HDR_SIZE]
data = data[HPIMAGE_HDR_SIZE:]

offsets_map["HPIMAGE_HDR"] = global_offset
global_offset += HPIMAGE_HDR_SIZE

print("[+] iLO HPIMAGE header :")

with open(outdir + "/hpimage.hdr", "wb") as fff:
    fff.write(hpimage_header)

img_hdr = HpImageHeader.from_buffer_copy(hpimage_header)
img_hdr.dump()

boot_block = data[-BOOT_BLOCK_SIZE:]
data = data[:-BOOT_BLOCK_SIZE]
hdr0 = boot_block[-IMG_HDR_SIZE:]


print("\n\n")
print("[+] iLO boot block footer:")

img0 = ImageHeader.from_buffer_copy(hdr0)
img0.dump()

check_header_crc(hdr0, img0)

mod_list.append(img0)

with open(outdir + "/bootblock.hdr", "wb") as fff:
    fff.write(hdr0)

with open(outdir + "/bootblock.sig", "wb") as fff:
    fff.write(bytearray(img0.signature))

bootblock = boot_block[:img0.backward_crc_offset]
with open(outdir + "/bootblock.raw", "wb") as fff:
    fff.write(bootblock)

check_img_crc(bootblock, img0)


hdr1 = bootblock[-IMG_HDR_SIZE:]

print("\n\n")
print("[+] iLO Bootstrap footer 1:")

img1 = ImageHeader.from_buffer_copy(hdr1)
img1.dump()
mod_list.append(img1)

check_header_crc(hdr1, img1)
bootstrap = boot_block[:img1.backward_crc_offset]
check_img_crc(bootstrap, img1)

with open(outdir + "/bootstrap.hdr", "wb") as fff:
    fff.write(hdr1[:IMG_HDR_SIZE])

with open(outdir + "/bootstrap.sig", "wb") as fff:
    fff.write(bytearray(img1.signature))

# signature is computed on backward_crc_offset size
# if img1.decompressed_size < img1.backward_crc_offset:
#     bootstrap = bootstrap[:img1.decompressed_size]

bootstrap = bootstrap[:img1.backward_crc_offset]

with open(outdir + "/bootstrap.bin", "wb") as fff:
    fff.write(bootstrap)


#------------------------------------------------------------------------------
# extract target info

targetListsize = unpack_from("<L", data)[0]

print("\n\n")
print("[+] iLO target list: %x element(s)" % (targetListsize))

data = data[4:]
global_offset += 4

for i in range(targetListsize):
    raw = data[:0x10]
    dev = ""
    id = uuid.UUID(raw.hex())
    if id in TARGETS:
        dev = TARGETS[id]

    print("    target 0x%x (%s)" % (i, dev))
    print(hexdump(raw))
    data = data[0x10:]
    global_offset += 0x10

data = data[4:]
global_offset += 4

#------------------------------------------------------------------------------
# extract modules

ilo_num = 0

while True:
    print("\n-------------------------------------------------------------------------------")
    print("[+] iLO Header %d" % (ilo_num))

    ilo_header = data[:IMG_HDR_SIZE]
    data = data[IMG_HDR_SIZE:]

    print(IMG_LIST)
    print(ilo_num)
    print(IMG_LIST[ilo_num])


    with open(outdir + "/%s.hdr" % IMG_LIST[ilo_num], "wb") as fff:
        fff.write(ilo_header)

    img_header = ImageHeader.from_buffer_copy(ilo_header)
    img_header.dump()

    check_header_crc(ilo_header, img_header)
    mod_list.append(img_header)

    with open(outdir + "/%s.sig" % IMG_LIST[ilo_num], "wb") as fff:
        fff.write(bytearray(img_header.signature))

    module = data[:img_header.compressed_size]
    with open(outdir + "/%s.raw" % IMG_LIST[ilo_num], "wb") as fff:
        fff.write(module)

    check_img_crc(module, img_header)

    # insert img into offsets map
    offsets_map["%s_HDR" % IMG_LIST[ilo_num].upper()] = global_offset
    global_offset += IMG_HDR_SIZE
    offsets_map["%s" % IMG_LIST[ilo_num].upper()] = global_offset
    global_offset += img_header.compressed_size

    if (img_header.flags & 1) == 1:
        output_size = decompress_all(module, outdir + "/%s.bin" % IMG_LIST[ilo_num])
        print("output_size : 0x%08x\n" % (output_size))

        print("[+] Extracted %s.bin" % IMG_LIST[ilo_num])

    # skip padding bytes
    data = data[img_header.compressed_size:]
    mod_sig = pack("<L", img_header.fw_magic)
    sig_offset = data.find(mod_sig)

    #print("\n>> skip 0x%x" % sig_offset)

    if sig_offset == -1:
        print("[x] failed to find next module")
        break

    skip_bytes = sig_offset - 0x20
    data = data[skip_bytes:]
    global_offset += skip_bytes
    ilo_num += 1


print("\n-------------------------------------------------------------------------------")
print("[+] Modules summary (%d)" % (ilo_num+1))

for i, mod in enumerate(mod_list):
    print("    %2x) %30s, type 0x%02x, size 0x%08x, crc 0x%08x" % (i, mod.module.decode(), mod.type, mod.decompressed_size, mod.img_crc))


#------------------------------------------------------------------------------
# output offsets map

print("\n[+] Firmware offset map")
for part, offset in offsets_map.items():
    print("  > %30s at 0x%08x" % (part, offset))

with open(outdir + "/firmware.map", "wb") as fff:
    fff.write(json.dumps(offsets_map, sort_keys=True, indent=4, separators=(',', ': ')).encode())
