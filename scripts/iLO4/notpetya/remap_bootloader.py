import sys
if len(sys.argv) < 2:
    print("Usage: %s bootloader" % sys.argv[0])
    sys.exit(1)

f = sys.argv[1]
bootloader = open(f,"rb").read()
out=open(f+".remap","wb")
out.write(bootloader[:512])
out.write(b"\x00"*512)
out.write(bootloader[1*512:(1+33)*512])
