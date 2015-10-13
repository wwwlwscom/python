#!/usr/bin/env python

import psycopg2


dbh = psycopg2.connect('dbname=root user=root')
print "Connection successful."

cur = dbh.cursor()
cur.execute("select * from ch14")
cur.arraysize = 2

while 1:
	rows = cur.fetchmany()
	print "Obtained %d results from fetchmany()." % len(rows)
	if not len(rows):
		break
	for row in rows:
		print row

dbh.close()



