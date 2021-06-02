#
# hexdump.py Copyright (C) BERARD David
# https://github.com/polymorf/polytools/blob/master/polytools/hexdump.py
#

# coding: utf8
import string


def load_hexdump(data):
	out=""
	for line in data.split("\n"):
		if "│" not in line:
			continue
		hex_data = line.split("│")[1]
		hex_data = hex_data.replace(" ","")
		hex_data = hex_data.replace("\x1b[0m","")
		hex_data = hex_data.replace("\x1b[36;1m","")
		out+=hex_data.decode("hex")
	return out

def hexdump(buf, title="", color=6, start=0, remove_dup=True):
	color_start = "" #"\033[3%d;1m" % color
	color_start_no_bold = "" #"\033[0m\033[3%dm" % color
	color_stop = "" #"\033[0m"

	address_format_size = len("0x%08x " % (len(buf) + start))
	space_before = " "*address_format_size

	out=("%s%s┌"+"─"*49+"┬"+"─"*18+"┐%s\n") % (space_before, color_start,color_stop)
	if title != "":
		dashlen = int((46-len(title))/2)
		out=("%s%s┌"+"─"*dashlen+"  "+title+"  "+"─"*(dashlen-(1-(len(title)%2)))+"┬"+"─"*18+"┐%s\n") % (space_before, color_start,color_stop)
	last_is_dup = False
	for i in range(0,len(buf),16):
		if remove_dup:
			if i != 0 and (i+16) < len(buf):
				if buf[i:i+16] == buf[i-16:i] and buf[i:i+16] == buf[i+16:i+32]:
					if not last_is_dup:
						out+="%s%s* ┆ %s" % (space_before[:-2], color_start, color_start_no_bold)
						out+="⇩"*47
						out+="%s ┆ %s" % (color_start, color_start_no_bold)
						out+="⇩"*16
						out+=" %s┆%s\n" % (color_start, color_stop)
					last_is_dup = True
					continue
				else:
					last_is_dup=False
		out+="%s0x%08x │ %s" % (color_start,i+start,color_stop)
		for j in range(16):
			if i+j < len(buf):
				if type(buf) == bytes:
					out+="%02x " % (buf[i+j])
				else:
					out+="%02x " % (ord(buf[i+j]))
			else:
				out+="   "
		out+="%s│ %s" % (color_start,color_stop)
		for j in range(16):
			if i+j < len(buf):
				char = buf[i+j]
				if type(char) == int:
					char = chr(char)
				if char in string.printable and char not in "\t\n\r\x0b\x0c":
					out+="%s" % (char)
				else:
					out+="."
			else:
				out+=" "
		out+=" %s│%s\n" % (color_start,color_stop)
	out+=("%s%s└"+"─"*49+"┴"+"─"*18+"┘%s") % (space_before, color_start,color_stop)
	print(out)
