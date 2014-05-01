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
# This tool can be used to check the SSL support on a list of 
# channels. Help can be viewed by running this file with --help
# 
# The list of channels should be included in the file mq_channels.txt 
# and a list of ciphers in the file ssl_ciphers.txt, both of these in 
# the same directory as this script.
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
import socket
import sys
import time
import os
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
parser.add_option("-t", "--target", action="store", dest="target", metavar="TARGET", help="Target IP address or hostname (required)")
parser.add_option("-p", "--port", action="store", dest="port", type= "int", metavar="port", help="Port to connect to (required)")
parser.add_option("-v", "--verbose", action="store", dest="verbose", metavar="VERBOSE", default="0", choices=["0","1"], help="Verbose output 1=yes 0=no (defaults to no)")
parser.add_option("-o", "--output", action="store", dest="output", default="0", choices=["0","1"], metavar="OUTPUT", help="Write output to file mq_ssl_checks.txt")

# Get the command line options
(options, args) = parser.parse_args()

# Mandate the use of a target and port
parser.check_required("-t")
parser.check_required("-p")

if options.target:
    target = options.target
else:
    sys.exit(0)

if options.port:
    port = options.port
else:
    sys.exit(0)

if options.verbose:
    verbose = int(options.verbose)
else:
    verbose = 0

if options.output:
    output = int(options.output)
else:
    output = 0

#
# Set up the strings and input/output files 
#

# Set up the MQ strings object
mq = build_packets()

# Open our file of Ciphers and Channels
file = 'ssl_ciphers.txt'
file2 = 'mq_channels.txt'
outputfile = 'mq_ssl_checks.txt'

# Open the input files for reading
try:
    fd = open(file2,'r')
except Exception:
    print 'Error, cannot open channels file'
    sys.exit(0)

# Open logfile for writing
if output == 1:
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
    fileHandle.write("Testing SSL Support for "+target+" on port "+str(port)+"\n\n")
    
for channel in fd.readlines():
    channel = channel.rstrip('\n') 
    if verbose == 1:
        print "=========================\nTesting Channel: "+channel
    # Prepare the handshake string
    send_string = mq.get_handshake(channel)

    # Check cleartext first
    outgoing = socket.socket ( socket.AF_INET,socket.SOCK_STREAM )
    try:
        outgoing.connect ( ( target, port ) )
    except Exception:
        print 'Error, cannot connect to host', target, 'on port '+str(port)
        sys.exit(0)
    else:
        if verbose == 1:
            print 'Connection suceeded to target host', target, 'on port '+str(port)

    cipher = "Cleartext"
    if verbose == 1:
        print "Trying cipher: "+cipher

    # Send the first handshake string
    outgoing.send(send_string)

    # Receive the response
    data = read_data(outgoing,0)

    # Check its MQ
    error = check_mq(data, verbose)

    if error == 1:
        print "Error detected exiting!"
        sys.exit(0)

    # Get the queue manager name
    queue_manager = check_status(data, verbose)

    if queue_manager == 0:
        error = check_return_code(queue_manager, outgoing, "", 1)
    else:
        print "Channel: "+channel
        print "SSL: None"
        print "Cipher: "+cipher
        print ''
        if fileHandle != 0:
            fileHandle.write("######################################\n")
            fileHandle.write("Channel: "+channel+"\n")
            fileHandle.write("SSL: None\n")
            fileHandle.write("Cipher: "+cipher+"\n")
        continue    

    try:
        fd2 = open(file, 'r')

    except Exception:
        print 'Error, cannot open ciphers file'
        sys.exit(0)

    # Now loop through the ciphers
    for cipher in fd2.readlines():
        splitcipher = cipher.split(',')
        cipher = splitcipher[0]
        version = int(splitcipher[1])

        if verbose == 1:
            print "-------\nTrying Cipher: "+cipher
        sslortls = ""
        # Set up the connection to our target
        if version == 0:
            ctx = SSL.Context(SSL.SSLv3_METHOD)
            sslortls = "SSLv3"
        else:
            ctx = SSL.Context(SSL.TLSv1_METHOD)
            sslortls = "TLSv1"

        ctx.set_cipher_list(cipher)

        outgoing = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        outgoing.connect((target, port))
        print "[*] Using " + cipher + " [" + sslortls + "] on " + target + ':'+str(port)
        # Send the first handshake string
        outgoing.send(send_string)

        # Receive the response
        data = read_data(outgoing,1)

        # Check its MQ
        error = check_mq(data,verbose)

        # Get the queue manager name 
        queue_manager = check_status(data,verbose)

        if queue_manager == 0:
            error = check_return_code(queue_manager, outgoing, "", 1)
        else:
            print "Channel: "+channel
            if version == 0:
                ssl = "SSLv3"
            else:
                ssl = "TLSv1"
            print "SSL: "+ssl
            print "Cipher: "+cipher
            print ''
            if fileHandle != 0:
                fileHandle.write("######################################\n")
                fileHandle.write("Channel: "+channel+"\n")
                fileHandle.write("SSL: "+str(ssl)+"\n")
                fileHandle.write("Cipher: "+cipher+"\n")
            continue
        check_status(data,verbose)
        #outgoing.shutdown()
        outgoing.close()
    fd2.close()

# Close the open files
if fileHandle != 0:
    fileHandle.write("######################################\n")
    fileHandle.close()
fd.close()
