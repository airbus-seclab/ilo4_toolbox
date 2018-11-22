import idaapi
import idc
from ctypes import *

# struct MAP_ENTRY
# {
  # MAP_ENTRY *next;
  # int ptr_name;
  # int base;
  # int size;
  # int access;
  # int field_14;
# };

# struct BSS_ENTRY
# {
#   void *ptr;
#   int init_value;
#   int size;
# };


class MapEntry(LittleEndianStructure):

    _fields_ = [
        ("next", c_uint32),
        ("name_addr", c_uint32),
        ("base", c_uint32),
        ("size", c_uint32),
        ("access", c_uint32),
        ("field_14", c_uint32),
    ]

    def to_str(self, ea):
        max_len = idaapi.get_max_ascii_length(ea, ASCSTR_C, 0)
        idaapi.make_ascii_string(ea, max_len, ASCSTR_C)
        return idc.GetString(ea, max_len, ASCSTR_C)

    def dump(self):
        print "  %20s - base 0x%08x - size 0x%08x - access : 0x%x" % (
            self.to_str(self.name_addr), self.base, self.size, self.access)

    def name(self):
        return "%s" % self.to_str(self.name_addr)



class BssEntry(LittleEndianStructure):

    _fields_ = [
        ("base", c_uint32),
        ("init_value", c_uint32),
        ("size", c_uint32),
    ]

    def dump(self, name=''):
        print "  memory area at 0x%08x - size 0x%08x - init value 0x%02x - \"%s\"" % (
            self.base, self.size,  self.init_value, name)



def make_segment(base, size, name):
    s = idc.get_segm_by_sel(base)
    if not s == 0xffffffff:
        return

    s = idaapi.segment_t()
    s.startEA = base
    s.endEA = base+size
    s.sel = 0
    s.bitness = 1
    s.comb = idaapi.scPub
    idaapi.add_segm_ex(s, name.strip('.').upper(), "", idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_SPARSE)



print "> parsing .secinfo entries:\n"

sid  = GetStrucIdByName('MAP_ENTRY')
ssize = idc.GetStrucSize(sid)

# for iLO5 1.30.35
SEC_INFO_LINKED_LIST = 0x410C580C

# for iLO5 1.20.33
SEC_INFO_LINKED_LIST = 0x410C480C

# for ILO5 1.37.06
SEC_INFO_LINKED_LIST = 0x410C580C


ea = SEC_INFO_LINKED_LIST
entries = []

while True:
    idc.MakeUnknown(ea, ssize, idc.DOUNK_DELNAMES)
    idaapi.doStruct(ea, ssize, sid);
    buf = idc.GetManyBytes(ea, ssize)

    entry = MapEntry.from_buffer_copy(buf)
    entries.append(entry)
    entry.dump()

    if entry.next == 0:
        break

    ea = entry.next


print "\n> setting-up segments:\n"

for entry in [e for e in entries if e.size != 0]:
    make_segment(entry.base, entry.size, entry.name())



bss_list = [e for e in entries if e.name() == '.secinfo']

if len(bss_list) == 1:
    print "\n> parsing BSS entries:\n"

    secinfo = bss_list[0]
    ea = secinfo.base
    sid  = GetStrucIdByName('BSS_ENTRY')
    ssize = idc.GetStrucSize(sid)

    while True:
        idc.MakeUnknown(ea, ssize, idc.DOUNK_DELNAMES)
        idaapi.doStruct(ea, ssize, sid);
        buf = idc.GetManyBytes(ea, ssize)
        bsse = BssEntry.from_buffer_copy(buf)

        elist =  [e for e in entries if (e.base == bsse.base and e.size != 0)]
        if len(elist) == 1:
            bsse.dump(elist[0].name())
        else:
            bsse.dump()

        ea += ssize
        if ea >= SEC_INFO_LINKED_LIST:
            break


print "\n[+] job done captain!\n"
