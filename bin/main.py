from rules import *

class sample():
   def __init__(self,fileName, location):
      self.fileName = fileName
      self.location = location
      self.sampleType = "unknown"
      self.ip = ''
      self.entropy = ''
      self.fileSize = ''
      self.minFileSize = ''
      self.suspiciousDllNumber = 0
      self.suspiciousCalls = []
      self.packing = ''
      self.totalDllCalls = 0

   def updateSampleType(self, sampleType):
      self.sampleType = sampleType   


file = 'test_data/malware/ghost-sample'
fileName = file.split("/")[-1]

sample = sample(fileName, file)

def malware_write(data):
   pass

def clean_write(data):
   pass

print ("starting classifier")

sample.ip = search_ip(sample.location) #dll search
sample.fileSize = fileSize(sample.location) #file size
sample.entropy, sample.minFileSize = entropy(sample.location, sample.fileSize) #entropy
sample.suspiciousDllNumber, sample.suspiciousCalls = suspiciousDllCalls(sample.location) #Suspicious DLLS
sample.packing = packing(sample.location) #Packing IDer


print ("#################################################")
print ("           Values found for %s                   "% sample.fileName)

for i in dir(sample):
   if "__" in i:
      continue
   else:
      print ("object.%s = %s" %(i, getattr(sample, i)))
