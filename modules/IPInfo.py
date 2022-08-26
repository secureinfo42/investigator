###################################################################################################
#  ___ ____ ___        __       
# |_ _|  _ \_ _|_ __  / _| ___  
#  | || |_) | || '_ \| |_ / _ \ 
#  | ||  __/| || | | |  _| (_) |
# |___|_|  |___|_| |_|_|  \___/ 
#                               
###################################################################################################

import loader

class IPInfo:

	## Init #########################################################################################

	def __init__(self,ip=""):
		try:
			self.api_key  = loader.API_KEYS['ipinfo']['key']
			self.base_url = loader.API_KEYS['ipinfo']['base_url']
			self.module_enabled = True
		except:
			self.module_enabled = False
		if ip:
			self.ip = ip
		return

	## Setters ######################################################################################

	def set_IP(self,ip):
		self.ip = ip

	## Getters ######################################################################################

	def get_info(self,ip=""):
		if not self.module_enabled: return False
		if not ip:
			ip = self.ip
		url = self.base_url + f'/{ip}' + f'?token={self.api_key}'
		ret = loader.get(url)
		# return(ret.text)
		json_data = loader.jsondecode(ret.text)
		return(json_data)


