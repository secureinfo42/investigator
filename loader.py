###################################################################################################
#  _     _ _                    _
# | |   (_) |__  _ __ __ _ _ __(_) ___  ___
# | |   | | '_ \| '__/ _` | '__| |/ _ \/ __|
# | |___| | |_) | | | (_| | |  | |  __/\__ \
# |_____|_|_.__/|_|  \__,_|_|  |_|\___||___/
#
################################################################################################### 

from json import JSONDecoder as jsondecode

import requests
requests.packages.urllib3.disable_warnings()

import warnings
warnings.filterwarnings("ignore")

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys
import re
import ssl
import OpenSSL
import json
import socket
import pygeoip
import logging
import socket
import simplejson
import hashlib
from my_config import *

from time      import sleep
from bs4       import BeautifulSoup
from os        import popen, system, unlink, stat
from hashlib   import sha1,md5,sha256

# from scapy.all import IP,ICMP,sr1,conf
# conf.verb = 0



###################################################################################################
#  _____                 _   _
# |  ___|   _ _ __   ___| |_(_) ___  _ __  ___
# | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
# |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
################################################################################################### 



###################################################################################################
# ┏━┓╻ ╻┏━┓╺┳╸┏━╸┏┳┓
# ┗━┓┗┳┛┗━┓ ┃ ┣╸ ┃┃┃
# ┗━┛ ╹ ┗━┛ ╹ ┗━╸╹ ╹
##

###################################################################################################
## Tools

def tool(exe):
  global PATHS
  for path in PATHS:
    try:
      stat(path+'/'+exe)
      return(path+'/'+exe)
    except:
      pass



###################################################################################################
# ┏━╸┏┓╻┏━╸┏━┓╺┳┓┏━╸┏━┓┏━┓
# ┣╸ ┃┗┫┃  ┃ ┃ ┃┃┣╸ ┣┳┛┗━┓
# ┗━╸╹ ╹┗━╸┗━┛╺┻┛┗━╸╹┗╸┗━┛
##

###################################################################################################
## URL

def urlencode(url):
  url = url.replace(':','%3a')
  url = url.replace('?','%3f')
  url = url.replace('&','%26')
  url = url.replace('/','%2f')
  url = url.replace('.','%2e')
  url = url.replace('+','%2b')
  return(url)

def urldecode(url):
  url = url.replace('%3a',':')
  url = url.replace('%3f','?')
  url = url.replace('%26','&')
  url = url.replace('%2f','/')
  url = url.replace('%2e','.')
  url = url.replace('%2b','+')
  return(url)

###################################################################################################
## Json

def jsonencode(mixed):
  try:
    return( simplejson.dumps(mixed) )
  except:
    return( simplejson.dumps('-') )

def jsondecode(text):
  try:
    return( simplejson.loads(text) )
  except:
    return( {'-'} )



###################################################################################################
# ┏━╸┏━┓┏━┓┏━┓┏━┓┏━┓
# ┣╸ ┣┳┛┣┳┛┃ ┃┣┳┛┗━┓
# ┗━╸╹┗╸╹┗╸┗━┛╹┗╸┗━┛
##

def perror(errtxt,errcode=""):
  global DEBUG
  msg = "Error: {}\n".format(errtxt)
  if DEBUG:
    try:
      open("/dev/stderr","wt").write(msg)
    except:
      print("{}".format(msg))
  if errcode:
    sys.exit(int(errcode))

def print_status(txt):
  txt = txt.upper()
  txt = f"[*] {txt} …"
  pdl = 42-len(txt)
  pad = " "*pdl
  txt = txt + pad
  # print(txt, file=sys.stderr, end="\r")
  print(txt, file=sys.stderr)
  sleep(.2)



###################################################################################################
# ┏━╸┏━┓┏┓╻╻ ╻┏━╸┏━┓╺┳╸┏━╸┏━┓┏━┓
# ┃  ┃ ┃┃┗┫┃┏┛┣╸ ┣┳┛ ┃ ┣╸ ┣┳┛┗━┓
# ┗━╸┗━┛╹ ╹┗┛ ┗━╸╹┗╸ ╹ ┗━╸╹┗╸┗━┛
##

###################################################################################################
## IP -> number

def ip2long(ip):
  ip    = [int(x) for x in ip.split(".")]
  long  = (ip[0] << 24)
  long += (ip[1] << 16)
  long += (ip[2] << 8)
  long += ip[3]
  return(long)

def ip2long_rev(ip):
  ip    = [int(x) for x in ip.split(".")]
  long  = (ip[3] << 24)
  long += (ip[2] << 16)
  long += (ip[1] << 8)
  long += ip[0]
  return(long)

def ip2hex(ip):
  ip = ["0"*(4-len(hex(int(x))))+hex(int(x)) for x in ip.split(".")]
  hx = ''.join(ip)
  hx = "0x"+hx.replace("0x","")
  return(hx)
 
###################################################################################################
## number -> IP

def long2ip(long):
  long = int(long)
  ip = [0,0,0,0]
  ip[0] = (long & 0xFF000000) >> 24
  ip[1] = (long & 0x00FF0000) >> 16
  ip[2] = (long & 0x0000FF00) >> 8
  ip[3] = (long & 0x000000FF)
  ip = [str(x) for x in ip]
  ip = '.'.join(ip)
  return(ip)

def long2ip_rev(long):
  long = int(long)
  ip = [0,0,0,0]
  ip[3] = (long & 0xFF000000) >> 24
  ip[2] = (long & 0x00FF0000) >> 16
  ip[1] = (long & 0x0000FF00) >> 8
  ip[0] = (long & 0x000000FF)
  ip = [str(x) for x in ip]
  ip = '.'.join(ip)
  return(ip)



###################################################################################################
# ╻ ╻┏━┓┏━┓╻ ╻┏━╸┏━┓┏━┓
# ┣━┫┣━┫┗━┓┣━┫┣╸ ┣┳┛┗━┓
# ╹ ╹╹ ╹┗━┛╹ ╹┗━╸╹┗╸┗━┛
##

###################################################################################################
## IP -> number

def md4(data):
  cmd = f'echo {data}|openssl dgst -md4'
  ret = popen(cmd).read().strip()
  md4 = ret.split('= ')[1]
  return(md4)

def md5(data):
  md5 = hashlib.sha1(data.encode()).hexdigest()
  return(md5)



###################################################################################################
# ╻ ╻┏━╸┏┓ 
# ┃╻┃┣╸ ┣┻┓
# ┗┻┛┗━╸┗━┛
##

###################################################################################################
## Get

def get(url,headers={}):
  global HEADERS
  current_headers = HEADERS
  current_headers.update(headers)
  s = requests.session()
  r = ''
  try:
    r = s.get(url,headers=current_headers,verify=False,allow_redirects=False)
    pass
  except Exception as e:
    raise
  return(r)

###################################################################################################
## Post

def post(url,post_data,headers={}):
  global HEADERS
  current_headers = HEADERS
  current_headers.update(headers)
  s = requests.session()
  r = ''
  try:
    r = s.post(url,post_data,headers=current_headers,verify=False,allow_redirects=False)
    pass
  except Exception as e:
    raise
  return(r)

###################################################################################################
## TCP

def send_tcp_pkt(host,port,verb):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  p = verb.encode() + b" / HTTP/1.1\r\n"
  r = b''
  try:
    c = s.connect((host,port))
    s.send(p)
    r = s.recv(65535)
    s.close()
  except:
    pass
  return(r)

###################################################################################################
## Parse

def parse_url(url):
  rgx = r"^(\w+)://([a-zA-Z0-9-_\.]+):?(\d*)/?"
  if not 'http' in url and not '://' in url:
    url = 'https://{}/'.format(url)
  rgx = re.compile(rgx)
  ret = re.findall(rgx,url)
  try:
    proto = ret[0][0]
    host  = ret[0][1]
    port  = ret[0][2]
  except IndexError:
    perror("unable to parse URL : `{}`".format(url),1)
  if not port:
    if proto == 'https': port = 443
    if proto == 'http':  port = 80
    if proto == 'ftp':   port = 21
    if proto == 'ftps':  port = 990
    if proto == 'rtsp':  port = 554
  if ret:
    try:
      ip = socket.gethostbyname(host)
    except socket.error:
      perror("unable to resolve host `{}`\n".format(host))
      sys.exit()
    ip = str(ip)
  email = 'contact@'+host
  return(url,proto,host,port,ip,email)

