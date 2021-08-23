import requests
from pwn import log
from common import err

template_url = "https://raw.githubusercontent.com/k1R4/Pwn/main/sps_template.py"

class Template():

	def __init__(self,args):
		self.url = template_url
		self.binary = args.binary
		self.libc = args.libc
		if args.remote == None:
			self.ip = None
		else:
			self.ip = args.remote.split(":")[0]
			self.port = args.remote.split(":")[1]
		self.generate()

	def get_template(self):
		resp = requests.get(self.url)
		if resp.status_code not in range(200,300):
			err("Error retrieving template!")
		return resp.text

	def generate(self):
		template = self.get_template()

		template = template.replace("BINARY", f"./{self.binary}")

		if self.libc != None:
			template = template.replace("LIBC", f"./{self.libc}").replace("l{", "").replace("}l", "")
		else:
			l_start, l_end = template.find("l{"), template.find("}l")
			if l_start == -1 or l_end == -1:
				err("Invalid template!")
			template = template[:l_start] + template[l_end+2:].lstrip("\n")

		if self.ip != None:
			template = template.replace("IP", self.ip).replace("PORT", self.port).replace("r{", "").replace("}r", "")
		else:
			r_start, r_end = template.find("r{"), template.find("}r")
			if r_start == -1 or r_end == -1:
				err("Invalid template!")
			template = template[:r_start] + template[r_end+2:].lstrip("\n")

		f = open("exp.py", "w")
		f.write(template)
		f.close()
		log.success("Template Generated!")
		exit()
