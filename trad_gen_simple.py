#!/usr/bin/env python

from email.MIMEText import MIMEText


message = """Hello,
	This is a test message from Chapter 9. I hope you enjoy it!
	--- Anonymous"""

msg = MIMEText(message)
msg['To'] = 'recipient@example.com'
msg['From'] = 'Test Sender <sender@example.com>'
msg['Subject'] = "Test Message, Chapter 9"

print msg.as_string()
