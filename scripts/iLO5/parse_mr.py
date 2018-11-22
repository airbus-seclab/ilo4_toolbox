import idc

def dump_memory_region(ea):

    idc.MakeStruct(ea,"MEMORY_REGION");

    id = idc.Dword(ea)
    flag1 = idc.Dword(ea+0x18)
    flag2 = idc.Dword(ea+0x1C)
    low = idc.Dword(ea+0x8)
    high = idc.Dword(ea+0x10)
    mask_low = idc.Dword(ea+0x20)
    mask_high = idc.Dword(ea+0x28)
    name = idc.Dword(ea+0x30)
    memory_region = idc.GetString(name, -1, idc.ASCSTR_C)
    print "    id: 0x%04x - flags 0x%x 0x%x - reg: %10s - low 0x%08x / high 0x%08x - mask 0x%08x / 0x%08x" % (id, flag1, flag2, memory_region, low, high, mask_low, mask_high)

    if memory_region.startswith("MR"):
        idc.set_name(ea, memory_region, idc.SN_PUBLIC)
    else:
        idc.set_name(ea, "MR_" + memory_region, idc.SN_PUBLIC)
        
# for iLO5 1.30.35
START_ADDR = 0x410CCC74

# for iLO5 1.20.33
START_ADDR = 0x410CBC74

# for iLO5 1.37.06
START_ADDR = 0x410CCC84


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
