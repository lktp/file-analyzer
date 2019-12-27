import sys
import math

'''
Things I want to build into here:
   1. Looks for an IP in the binary strings
   2. Looks for packing
   3. gets entropy
       -- Done
   4. get number of dll calls
   5. Get "suspicious dll calls"
   6. File type by header


'''

def fileSize(file):
   print("getting filesize")
   f = open(file, 'rb')
   byteArr = bytearray(f.read())
   f.close()
   return len(list(byteArr))

def entropy(file, fileSize):
   print("getting entropy")
   #Frequence List 
   f = open(file, 'rb')
   byteArr = bytearray(f.read())
   f.close()
   freqList = []
   for b in range(256):
      ctr = 0
      for byte in byteArr:
         if byte == b:
            ctr += 1
      freqList.append(float(ctr)/fileSize)
   print (freqList)
   #Shannon Entropy
   ent = 0.0
   for freq in freqList:
      if freq > 0:
         ent = ent + freq * math.log(freq, 2)
   ent = -ent
   # find min byte size
   minFileSize = ((ent * fileSize) / 8)
   return ent, minFileSize   


def search_ip():
   print ("looking for an IP in the binary")
   return False
