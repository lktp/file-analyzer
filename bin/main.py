from rules import *

class sample():
   def __init__(self):
      self.ip = ''
      self.entropy = ''
      self.fileSize = ''
      self.minFileSize = ''


   

file = '../test_data/malware/ghost-sample'

sample = sample()

def malware_write(data):
   pass

def clean_write(data):
   pass

print ("starting classifier")

sample.ip = search_ip()
sample.fileSize = fileSize(file)
sample.ent, sample.minFileSize = entropy(file, sample.fileSize)

print (sample.ent, sample.minFileSize)



