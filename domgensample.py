#!/usr/bin/env python

from xml.dom import minidom, Node

doc = minidom.Document()
doc.appendChild(doc.createComment("Sample XML Document -Chapter 8"))

book = doc.createElement('book')
doc.appendChild(book)

title = doc.createElement('title')
title.appendChild(doc.createTextNode('Sample XML Thing'))
book.appendChild(title)

author = doc.createElement('author')
book.appendChild(author)
name = doc.createElement('name')
author.appendChild(name)
firstname = doc.createElement('firstname')
name.appendChild(firstname)
firstname.appendChild(doc.createTextNode('Benjamin'))
name.appendChild(doc.createTextNode('  '))
lastname = doc.createElement('last')
name.appendChild(lastname)
lastname.appendChild(doc.createTextNode('Springy Widgets, Inc.'))

chapter = doc.createElement('chapter')
book.appendChild(chapter)
chapter.setAttribute('number', '1')
title = doc.createElement('title')
chapter.appendChild(title)
title.appendChild(doc.createTextNode('First Chapter'))

para = doc.createElement('para')
chapter.appendChild(para)
para.appendChild(doc.createTextNode("I think widgets are great. You should buy lots of them from "))

company = doc.createElement('company')
para.appendChild(company)
company.appendChild(doc.createTextNode('Springy widgets, Inc'))

para.appendChild(doc.createTextNode('.'))
print doc.toprettyxml(indent = ' ')
