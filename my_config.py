###################################################################################################
#   ____ _       _           _
#  / ___| | ___ | |__   __ _| |___
# | |  _| |/ _ \| '_ \ / _` | / __|
# | |_| | | (_) | |_) | (_| | \__ \
#  \____|_|\___/|_.__/ \__,_|_|___/
#
################################################################################################### 

DEBUG = True
import loader
# DIRECT_CONNETION = False
DIRECT_CONNETION = True

API_KEYS = loader.jsondecode().decode(open("keys.json").read())

HEADERS = {
  'User-Agent': 'noleak',
  'Accept': 'application/json',
	'Accept-Language': 'en',
	# 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:103.0) Gecko/20100101 Firefox/103.0',
	# 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
	# 'Accept-Encoding': 'gzip, deflate, br'
}

PATHS = (
  "/bin",
  "/usr/bin",
  "/usr/local/bin",
  "/opt/local/bin",
  "/opt/local/Library/Frameworks/Python.framework/Versions/3.10/bin/",
  "/sbin",
  "/usr/sbin",
  "/usr/local/sbin",
)
