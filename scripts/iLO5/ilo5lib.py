import os
import sys
from ctypes import *
from struct import pack
import zlib
import uuid
import binascii

DEVICES = {
    uuid.UUID("9d7b312fe3c9764dbff6b9d0d085a952") : "ILO",
    uuid.UUID("2e8d14aa096e3e45bc6f63baa5f5ccc4") : "SYSTEM_ROM",
    uuid.UUID("066df4b8db855c4694fbd106e61378ed") : "APML",
    uuid.UUID("9a43adb1d19dc141a4962da9313f1f07") : "CPLD",
    uuid.UUID("8aa2489e6c5819458405a04f84e27f0f") : "PIC",
    uuid.UUID("90aa533689703a45899c792827a50d67") : "NVME_BP_PIC",
    uuid.UUID("7760b86b75021446aae186618e8b1c27") : "POWER_SUPPLY",
    uuid.UUID("dffc32e2cbbc5347a99bf6b11c6eb074") : "EEPROM_I2C",
    uuid.UUID("18077fda4c441c49b9bfb5a9ccc5e6e8") : "FILES",
    uuid.UUID("0c4c1027c53a91498afbd1f3cd166fb4") : "LANGUAGE_PACK",
    uuid.UUID("71e134c72187c9489ed6d5bc7da5ef8d") : "INNOVATION_ENG",
    uuid.UUID("77564eb3dc21d345872b42f76fee9053") : "MANAGEMENT_ENG",
    uuid.UUID("e08ef28323841647ad1d878d0e5f5e21") : "VRD",
    uuid.UUID("4a4247f5ffa41540b986fc45d424731f") : "LOAD_MODULE",
    uuid.UUID("74c3639815012d4998688894c86c4513") : "PLDM",
    uuid.UUID("be70fc4287bbdb4b8e7cdb1c9af52957") : "COBOURG",
    uuid.UUID("c14c6fe6d99d8140921cff190388b7a8") : "TEST_SERVER",
    uuid.UUID("757797961ad2fc4b89f32dd085136fb6") : "EMB_MEDIA",
    uuid.UUID("c6b649e9bbcac8418ed1e4c28e602496") : "LICENSING"
}

TARGETS = {
    uuid.UUID("62a6644742b3c74f9ce9258c5d99e815"): "ILO_5",
    uuid.UUID("0000000000000000000000000000ffff"): "SERVER_ID",
    uuid.UUID("00000000000000000000000001FFFFFF"): "BIOS",
    uuid.UUID("00000000000000000000000001ffffff"): "BOOTBLOCK_0",
    uuid.UUID("00000000000000000000000001ffffff"): "BOOTBLOCK 1",
    uuid.UUID("00000000000000000000000000504dff"): "POWER PIC",
    uuid.UUID("000000000000000000000000ffffffff"): "NMVE_BP_PIC",
    uuid.UUID("4cb0f50e84b9984295f05b3fffffffff"): "OEM_DATA",
    uuid.UUID("ffffffffff00000000000cf38db966ea"): "BAY_1",
    uuid.UUID("ffffffffff00000000000cf38db966ea"): "BAY_2",
    uuid.UUID("ffffffffff00000000000cf38db966ea"): "BAY_3",
    uuid.UUID("ffffffffff00000000000cf38db966ea"): "BAY_4",
    uuid.UUID("ffffffffff00000000000cf38db966ea"): "BAY_5",
    uuid.UUID("ffffffffff00000000000cf38db966ea"): "BAY_6",
    uuid.UUID("ffffffffff00000000000cf38db966ea"): "BAY_7",
    uuid.UUID("ffffffffff00000000000cf38db966ea"): "BAY_8",
    uuid.UUID("f87d8fe20eb94f4bffffffffffffffff"): "ASIC_ID",
    uuid.UUID("47a4b1a62a384f5affffffffffffffff"): "IE_ID",
    uuid.UUID("47a4b1a62a384f5affffffffffffffff"): "ME_ID",
}

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

def check_header_crc(hdr, img):
    crc = (zlib.crc32(hdr[:0x58] + hdr[0x60:0x100]) & 0xffffffff)
    print("\n[+] header crc ok: 0x%08x" % crc)
    if crc != img.header_crc:
        print("[x] failed to check header crc: 0x%08x" % img.header_crc)
        sys.exit()

def check_img_crc(mod, img):
    crc = (zlib.crc32(mod) & 0xffffffff)
    print("[+] image crc ok : 0x%08x\n" % crc)
    if crc != img.img_crc:
        print("[x] failed to check image crc: 0x%08x" % img.img_crc)
    return crc

class HpImageHeader(LittleEndianStructure):

    _fields_ = [
        ("img_magic", c_char * 0x8),
        ("major", c_byte),
        ("minor", c_byte),
        ("field_A", c_ushort),
        ("device_id", c_byte * 0x10),
        ("field_1C", c_uint),
        ("field_20", c_uint),
        ("field_24", c_uint),
        ("field_28", c_uint),
        ("field_2C", c_uint),
        ("field_30", c_uint),
        ("field_34", c_uint),
        ("field_38", c_uint),
        ("field_3C", c_uint),
        ("version", c_char * 0x20),
        ("name", c_char * 0x40),
        ("gap", c_byte * 0x400),
    ]

    def to_str(self, byte_array):
        return str(bytearray(byte_array))

    def dump(self):
        print "  > img_magic          : %s" % self.to_str(self.img_magic)
        print "  > version major      : 0x%x" % self.major
        print "  > version minor      : 0x%x" % self.minor
        print "  > field_A            : 0x%02x" % self.field_A

        dev = ""
        id = uuid.UUID(self.to_str(self.device_id).encode("hex"))
        if id in DEVICES:
            dev = DEVICES[id]

        print "  > device id          : %s" % dev
        print hexdump(self.to_str(self.device_id))
        print "  > field_1C            : 0x%x" % self.field_1C
        print "  > field_20            : 0x%x" % self.field_20
        print "  > field_24            : 0x%x" % self.field_24
        print "  > field_28            : 0x%x" % self.field_28
        print "  > field_2C            : 0x%x" % self.field_2C
        print "  > field_30            : 0x%x" % self.field_30
        print "  > field_34            : 0x%x" % self.field_34
        print "  > field_38            : 0x%x" % self.field_38
        print "  > field_3C            : 0x%x" % self.field_3C
        print "  > version             : %s" % self.to_str(self.version)
        print "  > name                : %s" % self.to_str(self.name)
        print "  > gap"


class ImageHeader(LittleEndianStructure):

    _fields_ = [
        ("module", c_char * 0x20),
        ("fw_magic", c_uint),
        ("header_type", c_uint),
        ("field_28", c_short),
        ("type", c_short),
        ("flags", c_uint),
        ("field_30", c_uint),
        ("field_34", c_uint),
        ("field_38", c_uint),
        ("backward_crc_offset", c_uint),
        ("forward_crc_offset", c_uint),
        ("img_crc", c_uint),
        ("compressed_size", c_uint),
        ("decompressed_size", c_uint),
        ("field_50", c_uint),
        ("field_54", c_uint),
        ("crypto_params_index", c_ushort),
        ("crypto_params_index2", c_ushort),
        ("header_crc", c_uint),
        ("field_60", c_uint),
        ("field_64", c_uint),
        ("field_68", c_uint),
        ("field_6C", c_uint),
        ("field_70", c_uint),
        ("field_74", c_uint),
        ("field_78", c_uint),
        ("field_7C", c_uint),
        ("copyright", c_char * 0x80),
        ("signature", c_byte * 0x200),
        ("gap", c_byte * 0x4FC),
        ("fw_magic_end", c_uint),
    ]

    def to_str(self, byte_array):
        return str(bytearray(byte_array))

    def dump(self):
        print "  > module                  : %s" % self.to_str(self.module)
        print "  > fw_magic                : 0x%x" % self.fw_magic
        print "  > header_type             : 0x%x" % self.header_type
        print "  > field_28                : 0x%x" % self.field_28
        print "  > type                    : 0x%x" % self.type
        print "  > flags                   : 0x%x" % self.flags
        print "  > field_30                : 0x%x" % self.field_30
        print "  > field_34                : 0x%x" % self.field_34
        print "  > field_38                : 0x%x" % self.field_38
        print "  > backward_crc_offset     : 0x%x" % self.backward_crc_offset
        print "  > forward_crc_offset      : 0x%x" % self.forward_crc_offset
        print "  > img_crc                 : 0x%x" % self.img_crc
        print "  > compressed_size         : 0x%x" % self.compressed_size
        print "  > decompressed_size       : 0x%x" % self.decompressed_size
        print "  > field_50                : 0x%x" % self.field_50
        print "  > field_54                : 0x%x" % self.field_54
        print "  > crypto_params_index     : 0x%x" % self.crypto_params_index
        print "  > crypto_params_index 2   : 0x%x" % self.crypto_params_index2
        print "  > header_crc              : 0x%x" % self.header_crc
        print "  > field_60                : 0x%x" % self.field_60
        print "  > field_64                : 0x%x" % self.field_64
        print "  > field_68                : 0x%x" % self.field_68
        print "  > field_6C                : 0x%x" % self.field_6C
        print "  > field_70                : 0x%x" % self.field_70
        print "  > field_74                : 0x%x" % self.field_74
        print "  > field_78                : 0x%x" % self.field_78
        print "  > field_7C                : 0x%x" % self.field_7C
        print "  > copyright               : %s" % self.to_str(self.copyright)
        print "  > signature"
        print hexdump(self.to_str(self.signature))
        print "  > fw_magic_end       : 0x%x" % self.fw_magic_end

# decompress extracted images
window=['\0']*0x1000
wchar = 0

def decompress_all(data,fname,chunks=0x10000):
    fff = open(fname, "wb")

    while len(data)>0:
        ret = decompress(data[:chunks],fff)
        if len(data) < chunks:
            if ret == 0:
                data = ""
            else:
                data = data[-ret:]
            ret = decompress(data[:chunks],fff,limit=0)
            if ret == 0:
                data = ""
            else:
                data = data[-ret:]
        else:
            data = data[chunks-ret:]

    fff.close()
    return os.path.getsize(fname)


def decompress(data, fff, limit=16):
    global window,wchar
    out=""

    while len(data)>limit:
        comp=ord(data[0])
        data=data[1:]

        for i in xrange(8):
            if limit == 0:
                if len(data) == 0:
                    break
            if ((comp>>(7-i))&0x1) == 1:
                out += data[0]
                window[wchar] = data[0]
                wchar = (wchar+1)%0x1000
                data = data[1:]
            else:
                x = (ord(data[0])>>4)+3
                ptr = wchar - (ord(data[1]) + ((ord(data[0])&0xf)<<8)) - 1
                for k in xrange(x):
                    out += window[(ptr+k)&0xfff]
                    window[wchar] = window[(ptr+k)&0xfff]
                    wchar = (wchar+1)%0x1000
                data = data[2:]

    fff.write(out)
    return len(data)


def compress(data):
    data = ("\x00"*0x1000) + data
    current_off = 0x1000
    oc = 0
    outbuff = ""
    tmp_buff = ""
    mark = 0
    while current_off < len(data):
        k = 3
        off = -1

        while data[current_off:current_off+k] in data[current_off-0x1000:current_off+k-1] and k<19 and (current_off + k) < len(data):
            k += 1

        k -= 1

        if k >= 3:
            off = data[current_off-0x1000:current_off+k-1].rfind(data[current_off:current_off+k])
            if off == 4095 and data[current_off:current_off+k] == data[current_off-0x1000+off-1:current_off-0x1000+off-1+k]:
                off -= 1

        if off == -1:
            mark |= (1<<(7-oc))
            tmp_buff += data[current_off]
            current_off += 1
        else:
            special = (((k-3)<<12) | ((-off-1)&0xfff)) &0xffff
            tmp_buff += pack(">H", special)
            current_off += k
        oc += 1

        if oc == 8:
            outbuff += chr(mark) + tmp_buff
            tmp_buff = ""
            oc = 0
            mark = 0

    while oc < 8:
        mark |= (1<<(7-oc))
        oc += 1
    outbuff += chr(mark) + tmp_buff

    return outbuff
