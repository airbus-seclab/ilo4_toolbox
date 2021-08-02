import idc


# for iLO5 1.20.33
START_ADDR = 0x410CBC74

# for iLO5 1.30.35
START_ADDR = 0x410CCC74

# for iLO5 1.37.06
START_ADDR = 0x410CCC84

# for iLO5 1.48.02
START_ADDR = 0x410CCC84

# for iLO5 2.33.16
START_ADDR = 0x410CECD4

# for ILO5 2.41.02
START_ADDR = 0x410CECD4

# for iLO5 2.44.17
START_ADDR = 0x410CFCFC


def dump_memory_region(ea):
    idc.create_struct(ea, -1, "MEMORY_REGION")

    mem_id = idc.get_wide_dword(ea)
    flag1 = idc.get_wide_dword(ea+0x18)
    flag2 = idc.get_wide_dword(ea+0x1C)
    low = idc.get_wide_dword(ea+0x8)
    high = idc.get_wide_dword(ea+0x10)
    mask_low = idc.get_wide_dword(ea+0x20)
    mask_high = idc.get_wide_dword(ea+0x28)
    name = idc.get_wide_dword(ea+0x30)
    memory_region = ida_bytes.get_strlit_contents(name, -1, idc.STRTYPE_C).decode()
    print("    id: 0x%04x - flags 0x%x 0x%x - name: %10s - low 0x%08x / high 0x%08x - mask 0x%08x / 0x%08x" % (mem_id, flag1, flag2, memory_region, low, high, mask_low, mask_high))

    if memory_region.startswith("MR"):
        idc.set_name(ea, memory_region, idc.SN_PUBLIC)
    else:
        idc.set_name(ea, "MR_" + memory_region, idc.SN_PUBLIC)


ea = START_ADDR
mod_base = START_ADDR

print("> parsing memory region entries:\n")

while True:
    ida_bytes.create_data(ea, FF_DWORD, 4, ida_idaapi.BADADDR)
    struct_addr = idc.get_wide_dword(ea)
    if struct_addr == 0:
        break

    x = idc.SetType(ea, "MEMORY_REGION *")
    dump_memory_region(struct_addr)
    ea += 4

print("[+] job done captain!")
