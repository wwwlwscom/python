#!/usr/bin/env python

import MySQLdb

print "Connecting..."
dbh = MySQLdb.connect(db = "foo")
print "Connection successful."
dbh.close()
