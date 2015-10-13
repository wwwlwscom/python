#!/usr/bin/env python

import psycopg2


dbh = psycopg2.connect('dbname=root user=root')
print "Connection successful."

cur = dbh.cursor()
cur.execute("select * from ch14")

for column in cur.description:
	name, type_code, display_size, internal_size, precision, scale, null_ok = column
	
	print "Column name:", name
	print "Type code:", type_code
	print "Display_size:", display_size
	print "Internal_size:", internal_size
	print "Precision:", precision
	print "Scale:", scale
	print "Null OK:", null_ok
	print

dbh.close()



