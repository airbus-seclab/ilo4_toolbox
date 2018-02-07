import idc

def dump_memory_region(ea):

    idc.MakeStruct(ea,"MEMORY_REGION");

    id = idc.Dword(ea)
    low = idc.Dword(ea+8)
    high = idc.Dword(ea+0xC)
    intv = idc.Dword(ea+0x14)
    name = idc.Dword(ea+0x20)
    memory_region = idc.GetString(name, -1, idc.ASCSTR_C)
    print "    flags: 0x%04x - int 0x%x- reg: %10s - low 0x%08x / high 0x%08x" % (id, intv, memory_region, low, high)

    if memory_region.startswith("MR"):
        idc.set_name(ea, memory_region, idc.SN_PUBLIC)

        
# for v 2.44.7 19-Jul-2016
START_ADDR = 0x200BCA00

ea = START_ADDR
mod_base = START_ADDR

print "> parsing memory region entries:\n"

while True:
    idc.MakeDword(ea)
    struct_addr = idc.Dword(ea)
    if struct_addr == 0:
        break

    x = idc.SetType(ea, "MEMORY_REGION *")
    dump_memory_region(struct_addr)
    ea += 4

print "[+] job done captain!"
