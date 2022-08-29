###################################################################################################
#  ____  _                        _____    _            
# | __ )(_)_ __   __ _ _ __ _   _| ____|__| | __ _  ___ 
# |  _ \| | '_ \ / _` | '__| | | |  _| / _` |/ _` |/ _ \
# | |_) | | | | | (_| | |  | |_| | |__| (_| | (_| |  __/
# |____/|_|_| |_|\__,_|_|   \__, |_____\__,_|\__, |\___|
#                           |___/            |___/      
###################################################################################################

import loader

class BinaryEdge:

	## Init #########################################################################################

	def __init__(self):
		try:
			self.api_key  = loader.API_KEYS['binaryedge']['key']
			self.base_url = loader.API_KEYS['binaryedge']['base_url']
			self.module_enabled = True
		except:
			self.module_enabled = False

	## Getters ######################################################################################

	def get_URL_reputation(self,needle):
		if not self.module_enabled: return False
		url = self.base_url + 'urlrep/' + f'?key={self.api_key}&email={needle}'
		ret = loader.get(url)
		json_data = loader.jsondecode(ret.text)
		return(json_data)

	def get_Email_Verify(self,needle):
		if not self.module_enabled: return False
		url = self.base_url + 'emailverify/' + f'?key={self.api_key}&email={needle}'
		ret = loader.get(url,headers={'X-Key': self.api_key})
		json_data = loader.jsondecode(ret.text)
		return(json_data)


