#-*- coding: cp949 -*-

import sys
import re
from struct import *

key = ""
res_filename = ""
obfCode = ""
deobFunc = ""

def splitObfCode() :
	global obfCode
	global deobFunc
	global key
	
	obfList = []
	print "[+] Extracing obfuscated code..."
	with open(sys.argv[1], 'r') as ef:
		for x in ef.readlines():
			if re.search("(unescape|eval).+?(eval|unescape).+?[=](\'\")?[0-9A-Fa-f]", x):
				for s in range(len(x.split("\""))):
					obfList.append(x.split("\"")[s]) 		# 25 is obfuscate code, 27 is function

	print "[+] Extracting deobfuscate function and find divide key"
	for x in range(len(obfList)):		# obfuscate code > 10000, 1400 < function code < 2000 , 1000 ~ 2000
		if len(obfList[x]) >= 5000:
			obfCode = obfList[x]
		elif len(obfList[x]) >= 1000 and len(obfList[x]) <= 2000:
			deobFunc = obfList[x].replace('\\/', '/').replace('\\\\', '\\')
			buf = deobFunc.split(";")
			for s in range(len(buf)):
				if "%=" in buf[s]:
					key = int(buf[s].split("=")[1])
		else:
			pass

def letsgo(code, func, divkey) :
	a = ""
	b = 0
	c = 0
	d = ""
	
	print "[+] Deobfuscate..."
	for i in range(0,2):
		for t in range(len(func)):
			c = ((c&127)<<25) | ((c&4294967168)>>7) + ord(func[t])
			c = unpack("l", pack("L", c))[0]
		a+="1"

	if c < 0:
		c = c & 0xffffffff
	
	qq = 1
	for t in range(0, len(code), 2):
		if t >= 8: # (1<<3)
			a = t % 8
		else:
			a = t
		b = int(hex(c)[a+2:a+4], 16)+qq
		
		qq+=1
		
		if re.match('^(\d{4})', str(b+744)):
			b = b % divkey
		d += chr((int((obfCode[t] + obfCode[t+1]), 16))^b)
	
	rf = open("%s" % res_filename, "w")
	rf.write(d)
	rf.close()

def main() :
	global res_filename
	if len(sys.argv) >= 2:
		splitObfCode()
		res_filename = sys.argv[1].split('.')[0]+"_decode.txt"
		letsgo(obfCode, deobFunc, key)
	else:
		print "Usage: %s dadong_obfuscated_filename" % sys.argv[0]
	
	

if __name__ == "__main__" :
	main()
