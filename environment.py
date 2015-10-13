#!/usr/bin/env python

import sys,socket

def getipaddrs(hostname):
	result = socket.getaddrinfo(hostname,None,0,socket.SOCK_STREAM)
	return [x[4][0] for x in result]

hostname = socket.gethostname()
print "Host name:",hostname

print "Fully-qualified name:",socket.getfqdn(hostname)
try:
	print "IP addresses:",", ".join(getipaddrs(hostname))
except socket.gaierror,e:
	print "Could't not get IP addresses:",e
