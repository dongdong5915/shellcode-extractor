#!/usr/bin/python

import argparse
try:
	import elftools
except ImportError:
	print "Install pyelftools..."
	print "Exiting..."
	exit(0)

from elftools.elf.elffile import ELFFile

def printFile(fileName,shellcode,format="C"):
	f = None
	payGen = splitPayload(shellcode)
	newShellcode = ""
	for s in payGen:
		newShellcode += '"' + s + '"' + '\n'
		
	if format=="C":
		fileName = fileName + ".c"
		code = '#include <stdio.h>\n\nconst char PAYLOAD[] = ' + newShellcode + ';\nint main(int argc, char **argv){\n\tvoid (*f)() = (void *)PAYLOAD;\n\tf();\n}\n'
		f = open(fileName,'w')
		f.write(code)
	elif format=="python":
		fileName = fileName + ".py"
		f = open(fileName,'w')
		code = ("#!/usr/bin/python\n\nfrom ctypes import *\nPAYLOAD = (" + newShellcode + ")\nPAYLOAD = create_string_buffer(PAYLOAD,len(PAYLOAD))\n"
			"shell = cast(PAYLOAD,CFUNCTYPE(c_void_p))\nshell()\n")
		f.write(code)
	if f:
		f.close()	

def getPayload(f,section=".text"):
	try:
		e = ELFFile(f)
		s = e.get_section_by_name(section)
		payload = []
		bytes = 0
		for c in s.data():
			k = hex(ord(c)).lstrip("0")
			if len(k) == 2:
				k = k[0] + "0" + k[1]
			payload.append(k)
			bytes += 1
		return "\\" + "\\".join(payload), bytes
	except Exception, e:
		print e
		exit(0)

def splitPayload(payload):
	for i in xrange(0,len(payload),20):
		yield payload[i:i+20]

def getRawShellcode(f,outFile,section=".text"):
	try:
		e = ELFFile(f)
		s = e.get_section_by_name(section)
		fileName = outFile + ".raw"
		f = open(fileName,'w')
		f.write(s.data())
	except Exception, e:
		print e
		exit(0)

	if f:
		f.close()
		
	
def main():
	parser = argparse.ArgumentParser(prog="sextractor",description="A simple Shellcode extractor from ELF assembly files")
	parser.add_argument("-f",help="the assembly file to process")
	parser.add_argument("-r",help="generate a raw shellcode file");
	parser.add_argument("-C",help="generates a C file containing the payload for testing purpose (do not append extension to file, program will do it for you)")
	parser.add_argument("-P",help="like -C except that generates a Python file")
	parser.add_argument("-w",help="show warnings for NULL bytes \\x00",action='store_true')
	parser.add_argument("-s",help="specify section to extract eg. '-s .text'")
	args = parser.parse_args()

	shellcode = ""
	bytes = 0
	section = ".text"
	inFile = None
	outFile = None
	warnings = False
	
	if args.s:
		section = args.s

	if args.w:
		warnings = True

	if not args.f:
		parser.print_help()
		exit(0)
	else:
		try:
			inFile = open(args.f,'rb')
		except:
			print "File " + args.f + " doesn't exists.."
			exit(0)		
		shellcode, bytes = getPayload(inFile,section)
		payGen = splitPayload(shellcode)
		print
		for s in payGen:
			if "00" in s and warnings:
				print '"' + s + '"' + ' <--- DANGER CONTAINS NULL BYTES '
			else:
				print '"' + s + '"'
		print
		print "[*] Your payload has [" + str(bytes) + "] bytes"
	
	if args.C:
		printFile(args.C,shellcode)
	if args.P:
		printFile(args.P,shellcode,format="python")

	if args.r:
		outFile = args.r
		getRawShellcode(inFile,outFile,section)


	if inFile:
		inFile.close()

if __name__ == "__main__":
	main()
