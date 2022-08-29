###################################################################################################
#  __  __     __        __    _
# |  \/  |_   \ \      / /__ | |_
# | |\/| | | | \ \ /\ / / _ \| __|
# | |  | | |_| |\ V  V / (_) | |_
# |_|  |_|\__, | \_/\_/ \___/ \__|
#         |___/
#                                       
###################################################################################################

import loader

class MyWot:

	## Init #########################################################################################

	def __init__(self):
		self.version  = 'v3'
		try:
			self.userID   = loader.API_KEYS['wot']['userID']
			self.apiKey   = loader.API_KEYS['wot']['apiKey']
			self.base_url = loader.API_KEYS['wot']['base_url']
			self.module_enabled = True
		except:
			self.module_enabled = False

	## Getters ######################################################################################

	def get_WOT_score(self,needle):
		if not self.module_enabled: return False
		url = self.base_url + self.version + f'/targets?t=' # f'urlrep/{self.version}' + f'?key={self.api_key}&url={needle}'
		ret = loader.get(url,headers={'x-user-id': self.userID, 'x-api-key': self.apiKey})
		json_data = loader.jsondecode(ret.text)
		return(json_data)

# -H "x-user-id: userID" -H "x-api-key: api-key"
