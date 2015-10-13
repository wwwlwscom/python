#!/usr/bin/env python

import socket, sys
from OpenSSL import SSL

cafile, host = sys.argv[1:]

def printx509(x509):
	fields = {'country_name': 'Country',
		'SP': 'State/Province',
		'L': 'Locality',
		'O': 'Organization',
		'OU': 'Organizational Unit',
		'CN': 'Common Name',
		'email': 'E-Mail'}

	for field, desc in fields.items():
		try:
			print "%30s: %s" % (desc, getattr(x509, field))
		except:
			pass
	cnverified = 0

def verify(connection, certificate, errnum, depth, ok):
	global cnverifie

	subject = certificate.get_subject()
	issuer = certificate.get_issuer()

	print "Certificate from:"
	printx509(subject)

	print "\nIssued By:"
	printx509(issuer)

	if not ok:
		print "Could not verify certificate."
		return 0

	if subject.CN == None or subject.CN.lower() != host.lower():
		print "Connected to %s, but got cert for %s" % (host, subject.CN)
	else:
		cnverified = 1
	
	if depth == 0 and not cnverified:
		print "Could not verify server name; failing."
		return 0

	print "-" * 70
	return 1


ctx = SSL.Context(SSL.SSLv23_METHOD)
ctx.load_verify_locations(cafile)

ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FALL_IF_NO_PEER_CERT, verify)

print "Creating socket..."
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print "done."

ssl = SSL.Connection(ctx, s)

print "Establishing SSL..."
ssl.connect((host, 443))
print "done."

print "Requesting document..."
ssl.sendall("GET / HTTP/1.0\r\n\r\n")
print "done."


while 1:
	try:
		buf = ssl.recv(4096)
	except SSL.ZeroRetrunError:
		break
	sys.stdout.write(buf)

ssl.close()


