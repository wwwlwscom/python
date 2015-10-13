#!/usr/bin/env python

import sys,socket

def getipaddrs(hostname):
	result = socket.getaddrinfo(hostname,None,0,socket.SOCK_STREAM)
	return [x[4][0] for x in result]

def gethostname(ipaddr):
	return socket.gethostbyaddr(ipaddr)[0]

try:
	hostname = gethostname(sys.argv[1])

	ipaddrs = getipaddrs(hostname)

except socket.herror,e:
	print "No host names available for %s;this may be normal." % sys.argv[1]
	sys.exit(0)
except socket.gaierror,e:
	print "Got hostname %s,but it could not be forward-resolved: %s" % (hostname, str(e))
	sys.exit(1)

	if not sys.argv[1] in ipaddrs:
		print "Got hostname %s,but on forward lookup," % hostname
		print "original IP %s did not appear in IP address list." % sys.argv[1]
		sys.exit(1)

print "Validated hostname:" ,hostname
