#!/usr/bin/env python

import socket,sys

host = 'localhost'
port = 51423

data = "x" * 1024

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((host,port))

byteswritten = 0
while byteswritten < len(data):
	startpos = byteswritten
	endpos = min(byteswritten + 1024,len(data))
	byteswritten += s.send(data[startpos:endpos])
	sys.stdout.write("Wrote %d bytes\r" % byteswritten)
	sys.stdout.flush()

s.shutdown(1)

print "All data send."
while 1:
	buf = s.recv(1024)
	if not len(buf):
		break
	sys.stdout.write(buf)
