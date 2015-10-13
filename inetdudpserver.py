#!/usr/bin/env python


import socket,time,sys

s = socket.fromfd(sys.stdin.fileno(),socket.AF_INET,socket.SOCK_SDGRAM)
message, address = s.recvfrom(8192)
s.connect(address)

for i in range(10):
	s.send("Reply %d: %s % (i + i,message))
	time.sleep(2)
s.send("ok,I'm done sending replies.\n")