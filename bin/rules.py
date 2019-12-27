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
   7. Get file size
       -- Done
   8. Get file minimum size
       -- Done
   9. Look for registry entries


'''

def packing(file):
   #returns one of three values, (yes|no|unknown)
   return "unknown"

def suspiciousDllCalls(file):
   #returns the number of suspicious DLL calls, as well as a library of suspicious DLL calls
   #Need to figure out how to use the library but the numbers will be used to start
   return 0, []

def totalDllCalls(file):
   #will be used to find the number of dll calls 
   return 0
   pass

def fileSize(file):
   #returns the filesize of the file
   print("getting filesize")
   f = open(file, 'rb')
   byteArr = bytearray(f.read())
   f.close()
   return round(len(list(byteArr)),2)

def entropy(file, fileSize):
   #returns the entropy and mine file size of file
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
   #Shannon Entropy
   ent = 0.0
   for freq in freqList:
      if freq > 0:
         ent = ent + freq * math.log(freq, 2)
   ent = -ent
   # find min byte size
   minFileSize = ((ent * fileSize) / 8)
   return round(ent,3), round(minFileSize,2)   


def search_ip(file):
   #searches for any IPs in the binary
   print ("looking for an IP in the binary")
   return False

