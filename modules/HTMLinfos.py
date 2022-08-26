###################################################################################################
#  _   _ _____ __  __ _     _        __           
# | | | |_   _|  \/  | |   (_)_ __  / _| ___  ___ 
# | |_| | | | | |\/| | |   | | '_ \| |_ / _ \/ __|
# |  _  | | | | |  | | |___| | | | |  _| (_) \__ \
# |_| |_| |_| |_|  |_|_____|_|_| |_|_|  \___/|___/
#                                                 
###################################################################################################


from bs4 import BeautifulSoup as bs
from re import findall
import loader

PROPERTIES_EXTERNAL = ['href','src']

class HTMLinfos:
  """
  Is not an API. It's a set of tests
  """

  ## Init #########################################################################################

  def __init__(self,url=''):
    self.buff = ''
    self.html = ''
    self.url  = ''
    if url:
      self.url = url
    return

  ## Setters ######################################################################################

  def set_Buffer(self,url=''):
    if not self.url and url:
      self.url = url
    self.buff = loader.get(url).text
    self.html = bs(self.buff,features="lxml")

  ## Getters ######################################################################################

  def get_TagsStats(self,url=''):
    if loader.DIRECT_CONNETION == False:
      loader.perror("*** DIRECT CONNECTION : NOT RECOMMENDED ***") ; return
    self.set_Buffer(url) # bruh '-'
    ret = {}
    html_tags = [x.name for x in self.html.find_all()]
    tags = sorted(set(html_tags))
    for tag in tags:
      count = self.html.find_all(tag)
      ret.update({tag: len(count)})
    ret.update({"#Total": len(html_tags)})
    return(ret)

  ## Getters ######################################################################################

  def get_External(self,url='',properties=''):
    """
    Get href and src properties
    """
    if loader.DIRECT_CONNETION == False:
      loader.perror("*** DIRECT CONNECTION : NOT RECOMMENDED ***") ; return
    global PROPERTIES_EXTERNAL
    if not properties:
      properties = PROPERTIES_EXTERNAL
    self.set_Buffer(url)
    ret = []

    for tag in self.html():
      for prop in properties:
        try:
          if tag[prop]:
            ret.append(tag[prop])
        except:
          pass

    return(ret)











