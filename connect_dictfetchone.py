#!/usr/bin/env python

import psycopg2

def dictfechone(cur):
	seq = cur.fetchone()
	if seq == None:
		return seq
	result = {}
	colnum = 0
	for column in cur.description:
		result[column[0]] = seq[colnum]
		colnum += 1
	return result

dbh = psycopg2.connect('dbname=root user=root')
print "Connection successful."

cur = dbh.cursor()
cur.execute("select * from ch14")

while 1:
	row = dictfechone(cur)
	if row is None:
		break
	print row

dbh.close()



