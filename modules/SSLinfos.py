###################################################################################################
#  ____ ____  _     _        __           
# / ___/ ___|| |   (_)_ __  / _| ___  ___ 
# \___ \___ \| |   | | '_ \| |_ / _ \/ __|
#  ___) |__) | |___| | | | |  _| (_) \__ \
# |____/____/|_____|_|_| |_|_|  \___/|___/
#                                         
###################################################################################################

import loader
import re
import socket
import ssl
import OpenSSL
from os import popen

class SSLinfos:
  """
  Is not an API. It's a set of tests
  """

  ## Init #########################################################################################

  def __init__(self):
    return

  ## Getters ######################################################################################

  def _parse_x509Date(self,x509_date):
    x509_date = x509_date.decode()
    year    = x509_date[0:4]
    month   = x509_date[4:6]
    day     = x509_date[6:8]
    hour    = x509_date[8:10]
    minutes = x509_date[10:12]
    return( year +"/"+month+"/"+day+"@"+hour+":"+minutes )

  def _get_AltNames(self,host,port):
    cmd  = 'openssl s_client -showcerts -connect %s:%s 2>/dev/null </dev/null' % (host,port)
    cmd += '| openssl x509 -noout -text 2>/dev/null'
    cmd += '| grep -oP "(?<=DNS:)[^,]+"'
    altnames = [ x.strip() for x in popen(cmd).readlines() ]
    return(altnames)

  def get_SSLProperties(self,host,ip,port):
    infos      = {}
    expiration,notBefore,notAfter,subject,altnames = "-","-","-","-","-"
    # try:
    cert       = ssl.get_server_certificate((host,port))
    x509       = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    # print("-"*100)
    # print(x509.get_notAfter())
    # print(x509.get_notBefore())
    # print("-"*100)
    subject    = x509.get_subject()
    subject    = "".join("/{0:s}={1:s}".format(name.decode(), value.decode()) for name, value in subject.get_components())
    expiration = x509.has_expired()
    notAfter   = self._parse_x509Date(x509.get_notAfter())
    notBefore  = self._parse_x509Date(x509.get_notBefore())
    altnames   = self._get_AltNames(host,port)
    # except:
    #   loader.perror("problem while gathering certificate informations")
    ret = {
      'is_expired': expiration,
      'not-before': notBefore,
      'not-after': notAfter,
      'subject': subject,
      'altnames': altnames
    }
    return(ret)

  def get_Protocols(self,host,port):
    results = {}
    return(results)



