###################################################################################################
#     _    _                    ___ ____  ____  ____  
#    / \  | |__  _   _ ___  ___|_ _|  _ \|  _ \| __ ) 
#   / _ \ | '_ \| | | / __|/ _ \| || |_) | | | |  _ \ 
#  / ___ \| |_) | |_| \__ \  __/| ||  __/| |_| | |_) |
# /_/   \_\_.__/ \__,_|___/\___|___|_|   |____/|____/ 
#                                                     
################################################################################################### 


import loader
from bs4 import BeautifulSoup as bs


class AbuseIPDB:

	## Init #########################################################################################

	def __init__(self,needle=""):
		try:
			self.base_url = loader.API_KEYS['abuseipdb']['base_url']
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
		url = self.base_url + f'{needle}' 
		ret = loader.get(url)

		html       = bs(ret.text,features="lxml")
		h3         = html('h3')[0]
		ip         = str(h3).split('<b>')[1].split('</b>')[0]
		found      = str(h3).split(' was ')[1].split(' in')[0]
		reports    = "-"
		confidence = "-"

		if 'This IP was reported' in ret.text:
			html_result = ret.text.split('<h3> <b><span class=click-to-copy>')[1]
			html_result = html_result.split('<table class=table style=margin-top:0>')[0]
			reports     = html_result.split('<p>This IP was reported <b>')[1].split('</b>')[0]
			if '</span>' in ip:
				ip = ip.split('>')[1].split('</')[0]
			if 'Confidence of Abuse is' in ret.text:
				confidence = html_result.split('Confidence of Abuse is <b>')[1].split('</b>')[0]

		json_data = {
			'ip': ip,
			'found': found,
			'reports': reports,
			'confidence': confidence,
		}

		# ret = loader.jsonencode(json_data)
		return(json_data)

