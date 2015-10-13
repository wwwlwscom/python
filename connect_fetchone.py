#!/usr/bin/env python

import psycopg2


dbh = psycopg2.connect('dbname=root user=root')
print "Connection successful."

cur = dbh.cursor()
cur.execute("select * from ch14types")
cur.arraysize = 2

while 1:
	row = cur.fetchone()
	if row is None:
		break
	print row

dbh.close()



