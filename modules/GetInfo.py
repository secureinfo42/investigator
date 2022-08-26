###################################################################################################
#   ____      _   ___        __       
#  / ___| ___| |_|_ _|_ __  / _| ___  
# | |  _ / _ \ __|| || '_ \| |_ / _ \ 
# | |_| |  __/ |_ | || | | |  _| (_) |
#  \____|\___|\__|___|_| |_|_|  \___/ 
#                                     
###################################################################################################

import loader
import re
import socket
#import pygeoip
import geoip2.database
from os import popen
from modules import ThreatURLS

CURL    = loader.tool('curl') 
WHOIS   = loader.tool('whois')
WAFW00F = loader.tool('wafw00f')
OPENSSL = loader.tool('openssl')

class GetInfo:
  """
  Is not an API. It's a set of tests
  """

  ## Init #########################################################################################

  def __init__(self):
    self.module_enabled = True
    return

  ## Getters ######################################################################################

  # ╺┳╸╻ ╻┏━┓┏━╸┏━┓╺┳╸   ╻┏┓╻┏━╸┏━┓
  #  ┃ ┣━┫┣┳┛┣╸ ┣━┫ ┃ ╺━╸┃┃┗┫┣╸ ┃ ┃
  #  ╹ ╹ ╹╹┗╸┗━╸╹ ╹ ╹    ╹╹ ╹╹  ┗━┛

  def get_ThreatInfo(self,ip,hostname):
    if not self.module_enabled: return False
    global CURL
    results = []
    for site in ThreatURLS.THREAT_URL_LIST:
      url = ThreatURLS.THREAT_URL_LIST[site]
      cmd = f'{CURL} -s "{url}"|grep -Ew "{ip}|{hostname}"'
      ret = popen(cmd).read()
      if ret:
        found = "True"
      else:
        found = "False"
      results.append( {site: found} )
    return(results)

  #------------------------------------------------------------------------------------------------

  # ╻ ╻╻ ╻┏━┓╻┏━┓
  # ┃╻┃┣━┫┃ ┃┃┗━┓
  # ┗┻┛╹ ╹┗━┛╹┗━┛

  def get_Whois(self,ip):
    if not self.module_enabled: return False
    global WHOIS
    results = []
    index = 0
    prev_index = -1
    item = {}

    cmd = f'whois {ip}|iconv -f iso-8859-1 -t utf-8'
    whois = popen(cmd,'r').readlines()

    for line in whois:
      line = line.strip()
      if len(line) == 0:
        index += 1
      if re.match(r'^%',line) or re.match(r'^#',line) or re.match(r'^remarks',line) or re.match(r'^Comment',line) or 'descr' in line or not line:
        continue
      whois_keyword = line.split(':')[0].strip()
      whois_data    = ' '.join(line.split(':')[1:]).strip()
      if( len(whois_data.strip()) ) > 1:
        if prev_index == index:
          item.update( {whois_keyword: whois_data} )
        else:
          item = {whois_keyword: whois_data}
          results.append( item )
      prev_index = index
    # ret = loader.jsonencode(results)
    # return(ret)
    return(results)

  #------------------------------------------------------------------------------------------------

  # ╻ ╻┏━╸┏━┓┏┓    ┏━┓╺┳╸┏━┓╺┳╸┏━┓
  # ┃┏┛┣╸ ┣┳┛┣┻┓╺━╸┗━┓ ┃ ┣━┫ ┃ ┗━┓
  # ┗┛ ┗━╸╹┗╸┗━┛   ┗━┛ ╹ ╹ ╹ ╹ ┗━┛

  def get_VerbStats(self,host,port):
    if not self.module_enabled: return False
    if loader.DIRECT_CONNETION == False:
      loader.perror("*** DIRECT CONNECTION : NOT RECOMMENDED ***") ; return
    results = []
    for verb in ['GET','POST','CONNECT','OPTIONS','PATCH','TRACE','PUT','HEAD','DELETE','ZZZ']:
      ret = loader.send_tcp_pkt(host,port,verb)
      errcode,title,size = '-','-','0'

      if b'\r\n' in ret:
        errcode = ret.split(b'\r\n')[0].split(b' ')[1]
      if b'<title>' in ret:
        title = ret.split(b'<title>')[1].split(b'</title>')[0]
      if b'Content-Length: ' in ret:
        size = ret.split(b'Content-Length: ')[1].split(b'\r\n')[0]

      stats = {'errcode': errcode, 'size': size, 'title': title}
      results.append( {verb: stats} )
    # ret = loader.jsonencode(results)
    # return(ret)
    return(results)

  #------------------------------------------------------------------------------------------------

  # ╻┏━╸┏┳┓┏━┓   ╻┏┓╻┏━╸┏━┓┏━┓
  # ┃┃  ┃┃┃┣━┛╺━╸┃┃┗┫┣╸ ┃ ┃┗━┓
  # ╹┗━╸╹ ╹╹     ╹╹ ╹╹  ┗━┛┗━┛

  def get_ICMPInfos(self,ip):
    if not self.module_enabled: return False
    if loader.DIRECT_CONNETION == False:
      loader.perror("*** DIRECT CONNECTION : NOT RECOMMENDED ***") ; return
    from scapy.all import IP,ICMP,sr1,conf
    conf.verb = 0

    pkt = IP(dst=ip)/ICMP(type=8,code=0)
    ans = sr1(pkt,timeout=2)
    ttl = '-'
    os  = 'Unknown'
    distance = '?'
    if ans:
      ttl = ans.ttl
      if ans.ttl > 64 and ans.ttl <= 128:
        distance = 128-ans.ttl
        os = 'Windows'
      elif ans.ttl <= 64:
        distance = 64-ans.ttl
        os = 'Linux'
      elif ans.ttl > 128:
        distance = 255-ans.ttl
        os = 'Gateway?'
    return( {'icmp': {'ttl':ttl, 'guessed-os':os, 'distance':str(distance)} } )

  #------------------------------------------------------------------------------------------------

  # ╻ ╻┏━┓┏━╸   ╻ ╻┏━┓┏━┓┏━╸
  # ┃╻┃┣━┫┣╸ ╺━╸┃╻┃┃┃┃┃┃┃┣╸ 
  # ┗┻┛╹ ╹╹     ┗┻┛┗━┛┗━┛╹  

  def do_wafw00f(self,url):
    if not self.module_enabled: return False
    if loader.DIRECT_CONNETION == False:
      loader.perror("*** DIRECT CONNECTION : NOT RECOMMENDED ***") ; return
    global WAFW00F
    infos = []
    cmd = "%s --output=- %s 2>/dev/null" % (WAFW00F,url)
    res = popen(cmd).read().strip()
    ret = []
    try:
      ret = res.split(url)[1]
      ret = re.sub(r'^\s+','',ret)
      ret = re.sub(r'\s+',' ',ret)
    except:
      pass
    return( {'wafw00f':ret} )

  #------------------------------------------------------------------------------------------------

  # ┏━┓┏━╸╻ ╻┏━╸┏━┓┏━┓┏━╸   ╺┳┓┏┓╻┏━┓
  # ┣┳┛┣╸ ┃┏┛┣╸ ┣┳┛┗━┓┣╸ ╺━╸ ┃┃┃┗┫┗━┓
  # ╹┗╸┗━╸┗┛ ┗━╸╹┗╸┗━┛┗━╸   ╺┻┛╹ ╹┗━┛

  def get_ReverseDNS(self,host,ip):
    """
    Reverse DNS resolution
    """
    reverse_name = []
    try:
      reverse_name = socket.gethostbyaddr(host)
    except:
      try:
        reverse_name = socket.gethostbyaddr(ip)
      except:
        loader.perror("unable to do a reverse resolution to %s (%s)" % (host,ip))
        return([host,ip])
    infos = []
    for i in reverse_name:
      if type(i) is list:
        for j in i:
          infos.append(j)
      else:
        infos.append(i)
    return(infos)

  #------------------------------------------------------------------------------------------------

  # ┏━╸┏━╸┏━┓   ╻┏━┓
  # ┃╺┓┣╸ ┃ ┃╺━╸┃┣━┛
  # ┗━┛┗━╸┗━┛   ╹╹  

  """
  def get_GeoIP_old(self,ip):
    GEOIP_DB = pygeoip.GeoIP("/usr/local/share/GeoIP/GeoIP.dat")
    country = GEOIP_DB.country_code_by_addr(ip)
    if not country:
      country = "Unknown"
    return(country)
  """

  def get_GeoIP(self,ip):
    with geoip2.database.Reader('GeoLite2-Country.mmdb') as reader:
      response = reader.country(ip)
      country = response.country.name
      return(country)




