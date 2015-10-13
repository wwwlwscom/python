#!/usr/bin/env python

import sys, email

msg = email.message_from_file(sys.stdin)

print " *** Headers in message: "
for header, value in msg.items():
	print header + ":"
	print " " + value

if msg.is_multipart():
	print "This program cannot handle MIME multipart messages; exiting."
	sys.exit(1)

print "-" * 78
if 'subject' in msg:
	print "Subject: ", msg['subject']
	print "-" * 78

print "Message Body:"
print

print msg.get_payload()
