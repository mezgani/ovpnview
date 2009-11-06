#-*- coding:utf-8 -*-

"""
__author__ = "MEZGANI Ali handrix@users.sourceforge.org"
__self.version__ = "0.1"
__date__ = "2007/06/06 23:46:07"
__copyright__ = "Copyright (c) securfox"
__license__ = "GPL"
__credits__ = "Thanks elwalida for support"""

""" WHOIS Search provides domain name registration information by IP"""

import time, os, sys
import socket

RECV=819200

class cwhois:
    global RECV
    def __init__(self,server,address,version):
        self.server=server
        self.address=address
	self.version=version

    def onWhois(self):
            socket.setdefaulttimeout(30)
            try:
                if self.version=='6' and socket.has_ipv6==True:
                    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                elif self.version=='4': s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:  
                    s.connect((self.server, 43))
                except socket.error, (errno, perror):
                    if errno in (115, 150): pass
                    else:
                       raise socket.error, (errno, perror)
		if self.server=="whois.arin.net" or self.server=="whois.lacnic.net":
        		s.send(self.address)
			s.send("\r\n")
			data=s.recv(4096)
	                s.send("\r\n")
		        #data = data + s.recv(RECV)
		        data = s.recv(RECV)
			s.close()
			return (data)
              
		else:

			data = s.recv(4096)
			s.send(self.address)
			s.send("\r\n")
                        time.sleep(2)
			data = data + s.recv(8192)
			s.close()
			return (data)
              
 	    except Exception, e:
                return ("Exception: %s"  % e)
          
