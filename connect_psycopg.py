#!/usr/bin/env python

import psycopg2

def getdsn(db = None, user = None, passwd = None, host = None):
	if user == None:
		import os, pwd
		user = pwd.getpwuid(os.getuid())[0]
	if db == None:
		db = user
	dsn = 'dbname = %s user = %s' % (db, user)
	if passwd != None:
		dsn += ' password=' + passwd
	if host != None:
		dsn += ' host=' + host
	return dsn


dsn = getdsn()
print "Connecting to %s " % dsn

dbh = psycopg2.connect(dsn)
print "Connection successful."

dbh.close()



