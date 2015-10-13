#!/usr/bin/env python

import psycopg2


rows = ({'num': 0, 'text': 'Zero'},
	{'num': 1, 'text': 'Item One'},
	{'num': 2, 'text': 'Item Two'},
	{'num': 3, 'text': 'Three'})


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

cur = dbh.cursor()
cur.execute("DELETE FROM ch14")
query = "INSERT INTO ch14 VALUES(%(num)s,%(text)s)"
for row in rows:
	cur.execute(query, row)
dbh.commit()

dbh.close()



