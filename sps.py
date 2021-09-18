#!/bin/python3

from pwn import *
from ret2libc import *
from ret2win import *
from common import *
from linker import *
from template import *
import argparse

modes = ["linker","offset","ret2libc","ret2win","template"]

def argparse_handler():
	parser = argparse.ArgumentParser(description='Solve simple pwn challenges',formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument("mode", help="""ret2win/ret2libc/ROP/shellcode
		ret2win   ---> Provide challenge binary and name of the win function
		ret2libc  ---> Provide challenge binary along with libc
		linker    ---> Find and patch challenge binary with correct linker for given libc
		offset    ---> Provide challenge binary to get RIP/EIP offset
		template  ---> Automatic template generation for given challenge
		\n""")
	parser.add_argument("binary", help="Path to challenge binary")
	parser.add_argument("-i","--input", help="""File with input text to be given to binary before payload. Format:
		<input1> <output_before_input1>
		<input2> <output_before_input2>	
		payload <output_before_payload_entry>
		
		Note: append '\\n' to required input and output strings
		\n""",metavar="")
	parser.add_argument("-r","--remote", help="<remote_ip>:<port>",metavar="")
	parser.add_argument("-V","--verbose", action="store_true", help="Detailed logging via pwntools")
	parser.add_argument("-l","--libc", help="Path to libc binary",metavar="")
	parser.add_argument("-w","--winfn", help="Name of win function",metavar="")
	return parser.parse_args()

if __name__ == "__main__":
	args = argparse_handler()
	context.log_level = "info"

	if args.mode == "linker":
		LinkerPatcher(args)
	elif args.mode == "template":
		Template(args)

	if args.input != None:
		args.inputs = parse_input(args.input)
	else:
		args.inputs = [["payload\n",""]]

	if args.verbose:
		context.log_level = "debug"

	try:
		args.chall = context.binary = ELF(args.binary)
	except:
		err("Invalid challenge binary!")

	if args.mode not in modes:
		log.failure("Invalid mode!")
		exit()

	if context.arch == "amd64":
		args.offset = find_offset(args,8)
		log.info("RIP offset -> "+hex(args.offset))

		if args.mode == "offset":
			exit()

		if args.mode == "ret2libc":
			ret2libc64(args).solve()
		
		elif args.mode == "ret2win":
			ret2win(args).solve()

	elif context.arch == "i386":
		args.offset = find_offset(args,4)
		log.info("EIP offset -> "+hex(args.offset))

		if args.mode == "offset":
			exit()

		if args.mode == "ret2libc":
			ret2libc32(args).solve()

		elif args.mode == "ret2win":
			ret2win(args).solve()

	else:
		err("Architecture not supported!")