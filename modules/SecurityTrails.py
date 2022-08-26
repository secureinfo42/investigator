###################################################################################################
#  ____                       _ _        _____          _ _     
# / ___|  ___  ___ _   _ _ __(_) |_ _   |_   _| __ __ _(_) |___ 
# \___ \ / _ \/ __| | | | '__| | __| | | || || '__/ _` | | / __|
#  ___) |  __/ (__| |_| | |  | | |_| |_| || || | | (_| | | \__ \
# |____/ \___|\___|\__,_|_|  |_|\__|\__, ||_||_|  \__,_|_|_|___/
#                                   |___/                       
###################################################################################################

import loader

class SecurityTrails:

	## Init #########################################################################################

	def __init__(self,needle=""):
		try:
			self.api_key  = loader.API_KEYS['securitytrails']['key']
			self.base_url = loader.API_KEYS['securitytrails']['base_url']
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
		url = self.base_url + f'/{needle}' 
		ret = loader.get(url,headers={'apikey': self.api_key})
		# return(ret.text)
		json_data = loader.jsondecode(ret.text)
		return(json_data)

