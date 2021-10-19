import subprocess
import os
import wget as wg
from pwn import *
from common import err, cli_run

arch_dict = {"amd64":"x86_64-linux-gnu","i386":"i386-linux-gnu"}

class LinkerPatcher():

	def __init__(self,args):
		self.bin = args.binary
		self.libc = args.libc
		self.cwd = os.getcwd()
		self.log = None
		self.arch = None
		self.stripped = False
		self.compatibility()
		self.ver = self.get_version()

		cli_run(['mkdir','/tmp/sps'],self.cwd)
		self.patch()
		if self.stripped:
			self.unstrip()

	def compatibility(self):
		if self.libc == None:
			err("Libc not provided!")
		try:
			context.binary = ELF(self.libc)
		except:
			err("Invaild libc binary!")
		self.arch = context.arch
		if self.arch not in ["amd64","i386"]:
			err("Architecture not supported!")

		if b"not stripped" not in subprocess.check_output(['strings',f'{self.libc}']):
			self.stripped = True

		try:
			subprocess.run(['strings', '-h'], stdout=subprocess.DEVNULL)
		except:
			err("strings not found in path!")

		try:
			subprocess.run(['wget', '-h'], stdout=subprocess.DEVNULL)
		except:
			err("wget not found in path!")

		try:
			subprocess.run(['patchelf', '--version'], stdout=subprocess.DEVNULL)
		except:
			err("patchelf not found in path!")

		try:
			subprocess.run(['eu-unstrip', '--help'], stdout=subprocess.DEVNULL)
		except:
			err("eu-unstrip not found in path!")

	def get_version(self):
		verg = subprocess.Popen(f"strings {self.libc}".split(), stdout=subprocess.PIPE)
		grepr = subprocess.Popen(['grep', 'GNU C Library'], stdin=verg.stdout,
                     	stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out,err = grepr.communicate()
	
		try:
			self.ver = out.decode().split("GLIBC ")[1].split(")")[0]
			log.info(f"Libc Version: {self.ver}_{self.arch}")
			return self.ver
		except:
			err("Non-ubuntu libc found!")

	def get_deb(self,url,wd):
		try:
			self.log.status("Downloading deb package...")
			file = wg.download(url, out=wd)
			self.log.status("Deb package downloaded!")
			return file
		except:
			err("Failed to download deb package!")

	def extract_deb(self,file,wd):
		try:
			self.log.status("Extracting deb package...")
			cli_run(['ar','x',file],wd)
			cli_run(['sh','-c','tar xvf data.tar.*'],wd)
			self.log.status("Extracted deb package!")
		except:
			err("Failed to extract deb package!")

	def unstrip(self):
		print()
		self.log = log.progress("Unstrip")
		debug_deb_url = f"https://launchpad.net/ubuntu/+archive/primary/+files/libc6-dbg_{self.ver}_{self.arch}.deb"

		cli_run(['mkdir','/tmp/sps/unstrip'],self.cwd)
		file = self.get_deb(debug_deb_url,"/tmp/sps/unstrip")
		self.extract_deb(file,"/tmp/sps/unstrip")

		unstripr = subprocess.Popen(['eu-unstrip',self.libc, f'/tmp/sps/unstrip/usr/lib/debug/lib/{arch_dict[self.arch]}/libc-{self.ver[:4]}.so','-o',self.libc], stdout=subprocess.PIPE)
		cli_run(['rm','-r','/tmp/sps/unstrip'], self.cwd)

		self.log.status("Patching binary...")
		patchr = subprocess.Popen(['sh', '-c', f'patchelf --replace-needed libc.so.6 {self.cwd}/{self.libc} {self.bin}'], stdout=subprocess.PIPE)
		patchr.communicate()
		if patchr.returncode != 0:
			err("Patching failed!")
		self.log.success("Patching complete!")

	def patch(self):
		print()
		self.log = log.progress("Linker")
		vanilla_deb_url = f"https://launchpad.net/ubuntu/+archive/primary/+files/libc6_{self.ver}_{self.arch}.deb"

		cli_run(['mkdir','/tmp/sps/linker'],self.cwd)
		file = self.get_deb(vanilla_deb_url,"/tmp/sps/linker")
		self.extract_deb(file,"/tmp/sps/linker")

		cli_run(['sh','-c', f'mv /tmp/sps/linker/lib/{arch_dict[self.arch]}/ld-{self.ver[:4]}.so .'],self.cwd)
		cli_run(['rm','-r','/tmp/sps/linker'], self.cwd)

		self.log.status("Patching binary...")
		patchr = subprocess.Popen(['sh', '-c', f'patchelf --set-interpreter {self.cwd}/ld-{self.ver[:4]}.so {self.bin}'], stdout=subprocess.PIPE)
		patchr.communicate()
		if patchr.returncode != 0:
			err("Patching failed!")
		self.log.success("Patching complete!")
