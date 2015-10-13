#!/usr/bin/env python

import psycopg2


dbh = psycopg2.connect('dbname=root user=root')
print "Connection successful."

cur = dbh.cursor()
cur.execute("select * from ch14")
rows = cur.fetchall()
for row in rows:
	print row

dbh.close()



