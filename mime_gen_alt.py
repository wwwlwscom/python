#!/usr/bin/env python

from email.MIMEText import MIMEText
from email.MIMEMultipart import MIMEMultipart
from email import Utils, Encoders
import mimetypes, sys

def alternative(data, contenttype):
	maintype, subtype = contenttype.split('/')
	if maintype == 'text':
		retval = MIMEText(data, _subtype=subtype)
	else:
		retval = MIMEBase(maintype, subtype)
		retval.set_payload(data)
		Encoders.encode_base64(retval)

	return retval

message = """Hello,
This is a test message from Rock. I hope you enjoy it!

--Anonymous"""

messagehtml = """Hello,<P>
This is a <B>Great</B> test message from Rock,I hope you enjoy it!<P?
-- <I>Anonymous</I>"""

msg = MIMEMultipart('alternative')
msg['To'] = 'recipient@example.com'
msg['From'] = 'Test Sender <sender@example.com>'
msg['Subject'] = 'Test Message, Rock'
msg['Date'] = Utils.formatdate(localtime = 1)
msg['Message-ID'] = Utils.make_msgid()

msg.attach(alternative(message, 'text/plain'))
msg.attach(alternative(messagehtml, 'text/html'))
print msg.as_string()

