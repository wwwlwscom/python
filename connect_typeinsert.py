#!/usr/bin/env python

import psycopg2, time


dbh = psycopg2.connect('dbname=root user=root')
print "Connection successful."

cur = dbh.cursor()
cur.execute("""CREATE TABLE ch14types (
	mydate DATE,
	mytimestamp TIMESTAMP,
	mytime TIME,
	mystring varchar(30))""")

query = """INSERT INTO ch14types VALUES (
	%(mydate)s, %(mytimestamp)s, %(mytime)s, %(mystring)s)"""

rows = (\
	{'mydate': psycopg2.Date(2000, 12, 25),
	'mytimestamp': psycopg2.Timestamp(2000, 12, 15, 06, 30, 00),
	'mytime': psycopg2.Time(6, 30, 00),
	'mystring': 'Christmas - Wake Up!'},
	{'mydate': psycopg2.DateFromTicks(time.time()),
	'mytime': psycopg2.TimeFromTicks(time.time()),
	'mytimestamp': psycopg2.TimestampFromTicks(time.time()),
	'mystring': None})

cur.executemany(query, rows)
dbh.commit()

dbh.close()



