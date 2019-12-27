##############################################################################
#
#                        Author: LKTP
#           Purpose: To get data on files and eventually mess with ML
#           Bugs: None right now
#           ToDo: Move this list to git
#                1. Add file searches into the file folders
#                  1a.  Once it searches through the folder, it will move the files to another location
#                2. Do other shit             
#           ChangeLog: None yet
#
#
#
################################################################################



from rules import *
import os
import sys

class SampleClass():
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
      self.hash = ''

   def updateSampleType(self, sampleType):
      self.sampleType = sampleType   

def writer(object):
   #writes objects to the CSV
   if not os.path.exists("data.csv"):
      print ("data file doesnt exist, creating")
      f = open('data.csv', 'w')
      f.write("file Name, file sample type, file Hash, entropy, size, ip, min file size, packing, suspicious calls, suspiciousdll number, total dlls\n")
      f.close()
   f=open('data.csv', 'a')
   f.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" %(object.fileName, object.sampleType, object.hash, object.entropy, object.fileSize, object.ip, object.minFileSize, object.packing, object.suspiciousCalls, object.suspiciousDllNumber, object.totalDllCalls))
   f.close()


def classifer(sample):
   #starts the classifier
   print ("starting classifier")

   sample.ip = search_ip(sample.location) #dll search
   sample.fileSize = fileSize(sample.location) #file size
   sample.entropy, sample.minFileSize = entropy(sample.location, sample.fileSize) #entropy
   sample.suspiciousDllNumber, sample.suspiciousCalls = suspiciousDllCalls(sample.location) #Suspicious DLLS
   sample.packing = packing(sample.location) #Packing IDer


def output(sample):
   #prints to the screen
   print ("#################################################")
   print ("           Values found for %s                   "% sample.fileName)

   for i in dir(sample):
      if "__" in i:
         continue
      else:
         print ("object.%s = %s" %(i, getattr(sample, i)))


def main():
   #this will be the main controller for the different parts
   file = 'test_data/malware/ghost-sample'
   fileName = file.split("/")[-1]
   sample = SampleClass(fileName, file)
   classifer(sample)   
   writer(sample)
   output(sample)

if __name__ == "__main__":
   main()
