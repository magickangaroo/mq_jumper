#!/usr/bin/env python
# 
# This tool is distributed under a BSD licence. A copy of this 
# should have been included with this file.
#
# Copyright (c) 2007, Martyn Ruks
#
# This tool is designed for the purpose of performing security 
# testing only and is not intended to be used for unlawful 
# activities
#
# This tool can be used to check a host for MQ support by 
# attempting a handshake on each open port. 
# Help can be viewed by running this file with --help. 
# 
# The script must be passed an nmap file in greppable format and will use this to search
# for valid MQ services.
#
# Author: Martyn Ruks
# Version: 0.0.5
#
# Further information: martyn ({dot}) ruks <(at)> mwrinfosecurity {(dot)} com
#

# Add various required functions
import string
import optparse
import time
import binascii
import sys
import time
import os
import re
import socket
from OpenSSL import SSL
from shared_classes import *
from mq_strings import *
from struct import *
from optparse import OptionParser

#
# Extend optparse to make target options required
#

class OptionParser (optparse.OptionParser):

    def check_required (self, opt):
        option = self.get_option(opt)

        if getattr(self.values, option.dest) is None:
            self.error("%s option not supplied" % option)

#
# Command Line Options
#

parser = OptionParser()
parser.add_option("-f", "--file", action="store", dest="file", metavar="FILE", help="File to read greppable nmap output from (required)")
parser.add_option("-o", "--output", action="store", dest="output", metavar="OUTPUT", help="Output file for the results to be written to")
parser.add_option("-v", "--verbose", action="store", dest="verbose", metavar="VERBOSE", default="0", choices=["0","1"], help="Verbose output 1=yes 0=no (defaults to no)")

# Get the command line options
(options, args) = parser.parse_args()

# Mandate an nmap file
parser.check_required("-f")

if options.file:
    file = options.file
else:
    sys.exit(0)

if options.output:
    output = options.output
else:
    output = ''

if options.verbose:
    verbose = int(options.verbose)
else:
    verbose = 0

channel = 'SYSTEM.DEF.SVRCONN'

#
# Set up the strings and input/output files
#

# Set up the MQ strings object
mq = build_packets()

# Open the input file for reading
try:
    fd = open(file,'r')
except Exception:
    print 'Error, cannot open nmap file'
    sys.exit(0)

# Open logfile for writing
if output:
    # Open the log file for writing
    try:
        fileHandle = open ( outputfile, 'a' )
        if verbose == 1:
            print 'Output will be written to logfile', outputfile
    except Exception:
        print 'Error opening output file', outputfile, 'for writing'
        sys.exit(0)
else:
    fileHandle = 0

if fileHandle != 0:
    fileHandle.write("Searching for MQ on host for "+target+"\n\n")

# Prepare the handshake string
send_string = mq.get_handshake(channel)

for lineStr in fd.readlines():
    if re.match('Host:', lineStr):
        host = re.match("Host:\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\ \(", lineStr)
        target = host.group(1)
        print "Trying host: "+target
        if output:
            fileHandle.write("Trying host: "+target+"\n")
        ports = re.findall("([0-9]+)/open", lineStr)
        if ports:
            for port in ports:
                port = string.atoi(port)
                outgoing = socket.socket ( socket.AF_INET,socket.SOCK_STREAM )
                try:
                    outgoing.connect ( ( target, port ) )
                    print "Port: "+str(port)
                except Exception:
                    print 'Error, cannot connect to host', target, 'on port '+str(port)
                    continue
                else:
                    if verbose == 1:
                        print 'Connection suceeded to target host', target, 'on port '+str(port)
                    else:
                        pass

                # Send and receive the packets
                outgoing.settimeout(5)
                try:
                    outgoing.send ( send_string )

                    # Receive the response
                    data = read_data(outgoing,0)

                    # Check its MQ
                    error = check_mq(data,verbose)
                    if error == 1:
                        if verbose == 1:
                            print "Error detected exiting!"
                        continue

                    # Get the queue manager name
                    queue_manager = check_status(data,1)

                    outgoing.close()

                except Exception:
                    if verbose == 1:
                        print "Error socket timed out!"
                  
if output:
    fileHandle.close()
fd.close()
