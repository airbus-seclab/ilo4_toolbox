#!/usr/bin/python

import sys

# Patch signature check : BNE XX -> MOV R0, #0
PATCH = {"offset": 0x38BC, "size": 4, "prev_data": "4000001A", "patch": "0000A0E1"}

if len(sys.argv) < 2:
    print "usage: %s <bootloader.bin>" % sys.argv[0]
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    data = f.read()

check_data = data[PATCH["offset"]:PATCH["offset"]+PATCH["size"]]
if check_data != PATCH["prev_data"].decode("hex"):
    print "[-] Error, bad file content at offset %x" % PATCH["offset"]
    print "\t Expected:\t%s" % PATCH["prev_data"]
    print "\t Got:\t%s" % check_data.encode("hex")
    sys.exit(1)

data = data[:PATCH["offset"]] + PATCH["patch"].decode("hex") + data[PATCH["offset"]+PATCH["size"]:]

with open(sys.argv[1] + ".patched", "wb") as f:
    f.write(data)

print "[+] Patch applied to %s.patched" % sys.argv[1]
