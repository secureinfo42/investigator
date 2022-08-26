###################################################################################################
# __     __     _ ____  ____  
# \ \   / /   _| |  _ \| __ ) 
#  \ \ / / | | | | | | |  _ \ 
#   \ V /| |_| | | |_| | |_) |
#    \_/  \__,_|_|____/|____/ 
#                             
###################################################################################################

import loader

class VulDB:

	"""
  Exemples 
  --------
	vuldb = my_VulDB.VulDB()
	ret = vuldb.get_info('search','CVE-2014-6271')
	print(ret)
	"""

	## Init #########################################################################################

	def __init__(self):
		self.version  = 'v1/pay-as-you-go/'
		try:
			self.api_key  = loader.API_KEYS['vuldb']['key']
			self.base_url = loader.API_KEYS['vuldb']['base_url']
			self.module_enabled = True
		except:
			self.module_enabled = False
		return

	## Getters ######################################################################################

	def get_info(self,keyword,needle):
		if not self.module_enabled: return False
		post_data = {keyword: needle}	

		ret = loader.post(self.base_url+'&details=1',post_data,headers={'X-VulDB-ApiKey': self.api_key})
		# return(ret.text)
		json_data = loader.jsondecode(ret.text)
		return(json_data)


