### WORMSCAN.PY ###
# Scans for Linksys vulnerability on port 8083
# 2-19-2014

import os
import sys
import nmap
import socket
from socket import *

#variable declarations
wfile = open('Scan_2-18-14_PhonesPart2.txt','w')
tgtPort=8083


def connScan(tgtHost, tgtPort):
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((tgtHost, tgtPort))
		connSkt.send('GET /HNAP1/ HTTP/1.1\r\nHost: test\r\n\r\n')
		results = connCkt.recv(200)
		print '[+]%d/tcp open for %s' %(tgtPort, tgtHost)
		wfile.write('[+]%d/tcp open %s' %(tgtPort,tgtHost))
		print'[+] '+ str(results)
		wfile.write('[+] '+ str(results))
		connSkt.close()
	
	except:
		print'[-]%d/ tcp closed for %s'% (tgtPort,tgtHost)
		wfile.write('[-]%d/ tcp closed for %s' %(tgtPort, tgtHost))
		

nm=nmap.PortScanner()
nm.scan(hosts='10.209.9.0-255', arguments='-sn')
hosts_list = [(str(nm[x]['addresses']['ipv4'])) for x in nm.all_hosts()]

	
i=0
for x in hosts_list:
	connScan(x,tgtPort)
	
wfile.close()
#print(hosts_list[i].format(x))
#i+=1
#os.system('python pdf2txt.py -o temp.txt "%s"' %rfile)
#for x in hosts_list:
#os.system("echo 'GET /HNAP1/ HTTP/1.1\\r\\nHost: test\\r\\n\\r\\n'|ncat %s 8083" %x)
	