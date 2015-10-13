#!/usr/bin/env python

import psycopg2


dbh = psycopg2.connect('dbname=root user=root')
print "Connection successful."

cur = dbh.cursor()
cur.execute("select * from ch14")
cur.fetchone()

print "Obtained %d rows" % cur.rowcount

dbh.close()



