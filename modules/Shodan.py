###################################################################################################
#  ____  _               _             
# / ___|| |__   ___   __| | __ _ _ __  
# \___ \| '_ \ / _ \ / _` |/ _` | '_ \ 
#  ___) | | | | (_) | (_| | (_| | | | |
# |____/|_| |_|\___/ \__,_|\__,_|_| |_|
#                                      
###################################################################################################

import loader
import simplejson
from os import stat,popen

class Shodan:

  ## Init #########################################################################################

  def __init__(self):
    self.api_key  = loader.API_KEYS['shodan']['key']
    self.needle = ""

    self.exe = ""
    if self.set_exe():
      self.module_enabled = False
      return

    self.cmd = "{} search --separator ';' ".format(self.exe)
    self.cmd += "--fields "
    self.cmd += "ip,port,hostnames,city,org,ssl.cert.issuer.CN,ssl.cert.issuer.C,ssl.cert.issuer.L,http.server,http.title "
    self.module_enabled = True

  ## Setters ######################################################################################

  def set_exe(self):
    for path in ["/usr/bin",
                 "/usr/local/bin",
                 "/opt/local/Library/Frameworks/Python.framework/Versions/2.7/bin",
                 "/opt/local/Library/Frameworks/Python.framework/Versions/3.7/bin",
                 "/opt/local/Library/Frameworks/Python.framework/Versions/3.8/bin",
                 "/opt/local/Library/Frameworks/Python.framework/Versions/3.9/bin",
                 "/opt/local/Library/Frameworks/Python.framework/Versions/3.10/bin"
                ]:
      try:
        stat(path+"/shodan")
        self.exe = path+"/shodan"
        return True
      except:
        pass
    return False

  ## Getters ######################################################################################

  def get_exe(self):
    return(self.exe)

  def do_query(self,needle):
    if not self.module_enabled: return False
    self.cmd += "{} 2>/dev/null|grep .".format(needle)
    items = []
    results = [ x.rstrip() for x in popen(self.cmd).readlines() ]
    for line in results:
      line         = line.strip()
      ip           = line.split(';')[0]
      ip           = loader.long2ip(ip)
      port         = line.split(';')[1]
      rev          = line.split(';')[2]
      city         = line.split(';')[3]
      org          = line.split(';')[4]
      issuer       = line.split(';')[5]
      cert_country = line.split(';')[6]
      cert_city    = line.split(';')[7]
      http_server  = line.split(';')[8]
      http_title   = line.split(';')[9]
      item = {'ip':ip, 'port':port, 'rev':rev, 'org':org, 'http-srv': http_server, 'http-title': http_title}
      if item not in items:
        items.append( item )

    # ret = loader.jsonencode(items)
    return(items)





