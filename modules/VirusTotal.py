###################################################################################################
# __     ___               _____     _        _ 
# \ \   / (_)_ __ _   _ __|_   _|__ | |_ __ _| |
#  \ \ / /| | '__| | | / __|| |/ _ \| __/ _` | |
#   \ V / | | |  | |_| \__ \| | (_) | || (_| | |
#    \_/  |_|_|   \__,_|___/|_|\___/ \__\__,_|_|
#                                               
###################################################################################################

import loader

class VirusTotal:

	"""
  Exemples 
  --------
  virustotal = my_VirusTotal.VirusTotal()
  ret = virustotal.do_query('df209aaa50b2d78f835c2314a056c0e3')
	"""

	## Init #########################################################################################

	def __init__(self,needle=""):
		try:
			self.api_key  = loader.API_KEYS['virustotal']['key']
			self.base_url = loader.API_KEYS['virustotal']['base_url']
			self.module_enabled = True
		except:
			self.module_enabled = False
		if needle:
			self.needle = needle
		return

	## Getters ######################################################################################

	def do_query(self,needle=""):
		if not self.module_enabled: return False
		if not needle:
			needle = self.needle
		url = self.base_url + f'/files/{needle}' 

		ret = loader.get(url,headers={'x-apikey': self.api_key})
		# return(ret.text)
		json_data = loader.jsondecode(ret.text)
		return(json_data)

