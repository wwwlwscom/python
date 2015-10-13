#!/usr/bin/env python

import sys,socket

try:
	result = socket.gethostbyaddr(sys.argv[1])

	print "Primary hostname:"
	print " " + result[0]

	print "\nAddresses:"
	for item in result[2]:
		print " " + item

except socket.herror,e:
	print "Couldn't look up name:",e
