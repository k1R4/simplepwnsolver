import subprocess
import os
from pwn import *
from common import err

arch_dict = {"amd64":"x86_64-linux-gnu","i386":"i386-linux-gnu"}

class LinkerPatcher():

	def __init__(self,args):
		self.bin = args.binary
		self.libc = args.libc
		self.arch = None
		self.compatibility()
		self.patch()

	def compatibility(self):
		if self.libc == None:
			err("Libc not provided!")
		context.binary = ELF(self.libc)
		self.arch = context.arch
		if self.arch not in ["amd64","i386"]:
			err("Architecture not supported!")

		try:
			subprocess.run(['strings', '-h'], stdout=subprocess.PIPE)
		except:
			err("strings not found in path!")

		try:
			subprocess.run(['wget', '-h'], stdout=subprocess.PIPE)
		except:
			err("wget not found in path!")

		try:
			subprocess.run(['wget', '-h'], stdout=subprocess.PIPE)
		except:
			err("patchelf not found in path!")

	def get_version(self):
		verg = subprocess.Popen(f"strings {self.libc}".split(), stdout=subprocess.PIPE)
		grepr = subprocess.Popen(['grep', 'GNU C Library'], stdin=verg.stdout,
                     	stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out,err = grepr.communicate()
	
		if out.decode() == "":
			err("ELF provided isn't libc")
		else:
			self.ver = out.decode().split("GLIBC ")[1].split(")")[0]
			log.info(f"Libc Version: {self.ver}_{self.arch}")
			return self.ver

	def patch(self):
		deb_url = f"http://security.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_{self.get_version()}_{self.arch}.deb"
		self.ver = self.ver[:4]
		try:
			subprocess.run(['mkdir', '/tmp/sps'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
			log.info("Downloading deb package...")
			subprocess.run(['wget', deb_url, '-O', '/tmp/sps/libc.deb'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
			log.info("Extracting deb package...")
			subprocess.run(['ar','x','/tmp/sps/libc.deb'], cwd="/tmp/sps/", stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
			subprocess.run(['tar', 'xvf', 'data.tar.xz'], cwd="/tmp/sps", stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
		except:
			subprocess.run(['rm','-r','/tmp/sps'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
			err("Unable to download/extract deb package!")

		subprocess.run(['sh','-c', f'mv /tmp/sps/lib/{arch_dict[self.arch]}/ld-{self.ver}.so .'])
		subprocess.run(['rm','-r','/tmp/sps'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

		log.info("Patching binary...")
		patch = subprocess.Popen(['sh', '-c', f'patchelf --set-interpreter {os.getcwd()}/ld-{self.ver}.so {self.bin}'], stdout=subprocess.PIPE)
		patch.communicate()
		if patch.returncode != 0:
			err("Patching failed!")
		log.success("Patching complete!")
		exit()
		