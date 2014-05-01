#!/usr/local/bin/python2.7

'''
This is a Python script to scan a directory (and subdirectories) for files with certain extensions and compares them against virustotal.com.
If the script finds an infected file, it renames it.
The script is meant to be used as SABnzbd postprocessing script

Virustotal.com gives feedback based on the md5sum hash of a file.

Please note: virustotal requests are "limited to at most 4 requests of any nature in any given 1 minute time frame",
so do NOT use this script to scan your whole disk


This python script is based on this behaviour of the HTML page of virustotal:

$ wget https://www.virustotal.com/latest-scan/c33e6d2982957040355b703911c7a797 -o /dev/null -O - | grep -i -e " out of " -e "some of the"

  32 out of 50 antivirus
  Some of the detections were: Trojan.GenericKD.1477064, Trojan.GenericKD.1477064, RDN/Downloader.a!ox, Riskware ( 0040eff71 ), Riskware ( 0040eff71 ), Trojan.Badur!, WS.Reputation.1, Suspicious_Gen4.FNJQM, TROJ_SPNR.08LM13, Win32:Dropper-gen [Drp], Trojan.Win32.Badur.fyan, Trojan.GenericKD.1477064, Trojan.Win32.Badur.crimgd, Trojan.GenericKD.1477064, Trojan.GenericKD.1477064 (B), UnclassifiedMalware, Trojan.GenericKD.1477064, Trojan.DownLoader9.19493, Trojan.Win32.Generic!BT, TROJ_SPNR.08LM13, RDN/Downloader.a!ox, Mal/Generic-S, Trojan/Badur.cfo, Trojan/Win32.Badur, Trojan.GenericKD.1477064, Trojan.Badur, Trojan.Win32.Badur.ao, MSIL/TrojanDownloader.Agent.NI, Win32.SuspectCrc, Malware_fam.NB, Luhe.Fiha.A, HEUR/Malware.QVM03.Gen

'''

import os
import hashlib
import sys
import urllib2
import shutil
import json

apiKey = "xxx"
srv = "http://192.168.2.101:5050"


# Extensions to be scanned (note the dot at the beginning):
extlist = [ '.exe', '.com', '.apk' ]


# Function to calculate md5sum of a file
def md5_of_file(filename):
	md5 = hashlib.md5()
	with open(filename,'rb') as f: 
	    for chunk in iter(lambda: f.read(8192), b''): 
		 md5.update(chunk)
	return md5.hexdigest()


# Function to determine if virustotal says the md5sum is a virus/infection
def virustotal_scan(md5value):

	number = 0
	found = False
	names = ''

	baseurl = 'https://www.virustotal.com/latest-scan/'
	url = baseurl + md5value

	opener = urllib2.build_opener()
	opener.addheaders = [('User-agent', 'SABnzbd script version 0.1')]

	response = opener.open(url)
	html = response.read()

	for thisline in html.split('\n'):
		# We're interested in these lines in the html:
		# 	38 out of 50 antivirus
		# 	Some of the detections
		# So let's scan for them:
		if thisline.find(" out of ") >= 0:
			#print thisline.split()[0]
			try:
				number = int(thisline.split()[0])
				if number >=5:
					found = True
			except:
				number = 5
		if thisline.find("Some of the detections") >= 0:
			names = thisline[:128]

	return (found,names,number)


##############################################
##############################################
################# MAIN #######################
##############################################
##############################################

# Check the input parameter; there should be a valid directory name:

if len(sys.argv) < 2:
    sys.exit('Usage: %s directory-name' % sys.argv[0])

dirname = sys.argv[1]

if not os.path.exists(dirname):
    sys.exit('ERROR: Directory not found' % sys.argv[1])

# OK, let's start with scanning:

scannedfiles = 0 # no more than 4 per minute ...
virusfound = False

for root, dirs, files in os.walk(dirname):
    for file in files:
	extension = os.path.splitext(file)[1].lower()
	if extension in extlist:
		#print "extension is", extension
        	fullfilename = os.path.join(root, file)
		md5 = md5_of_file(fullfilename)
		#print fullfilename, md5
		virusfound, virusnames, number = virustotal_scan(md5)
		if virusfound:
			print "Virus found in", fullfilename, "!\n Info:\n", virusnames
			newfilename = fullfilename + '__INFECTED'
			os.rename(fullfilename, newfilename)
			shutil.rmtree(sys.argv[1])
			print "\n\nI deleted ",sys.argv[1]," for you!\n\n"
			nzb = sys.argv[2]
			nzb = nzb.split(".cp(")
			imdb = nzb[-1]
			imdb = imdb.replace(").nzb","")
			del nzb[-1]
			nzb='.cp('.join(nzb)
			print "\n\n"
            #search snatched movies
			url = srv+"/api/"+apiKey+"/media.list?release_status=snatched&status=active"
			u = urllib2.urlopen(url)
			obj = json.load(u)
			u.close()
                for x in range(0, len(obj['movies'])):
                    if imdb == obj['movies'][x]['library']['info']['imdb']:
                        url = srv+"/api/"+apiKey+"/movie.searcher.try_next?id="+str(obj['movies'][x]['id'])
                        u = urllib2.urlopen(url)
                        u.close()
                        print "\n\n I gave CP the command to ignore this NZB and search again"
		else:
			dummy = 0
			#print "No Virus found"
		scannedfiles += 1
		if scannedfiles > 4:
			print "Warning: you have now scanned more than 4 files ..."


if virusfound:
	sys.exit(number)
else:
	sys.exit(0)



