#! /usr/bin/env python
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
# This tool can be used to execute a PCF Inquire Q Manager command.
# You must have the appropriate level of access to issue this.
# 
# If you wish to use a client certificate with this tool uncomment 
# the relevant lines in this file and add location of certificate 
# and private key. The script will let you enter the passphrase at 
# runtime if required.
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
parser.add_option("-p", "--port", action="store", dest="port", type= "int", metavar="PORT", help="Port to connect to (required)")
parser.add_option("-c", "--channel", action="store", dest="channel", metavar="CHANNEL", help="Channel to connect to (defaults to SYSTEM.DEF.SVRCONN)")
parser.add_option("-s", "--ssl", action="store", dest="ssl", metavar="SSL", type="choice", default="0", choices=["0","1"], help="Use SSL 1=yes 0=no cipher and SSL version must be specified (defaults to no)")
parser.add_option("-v", "--verbose", action="store", dest="verbose", metavar="VERBOSE", default="0", choices=["0","1"], help="Verbose output 1=yes 0=no (defaults to no)")
parser.add_option("-i", "--cipher", action="store", dest="cipher", metavar="CIPHER", help="SSL cipher to use for connection (defaults to NULL-SHA)")
parser.add_option("-e", "--version", action="store", dest="version", metavar="VERSION", type="choice", default="0", choices=["0","1"], help="SSL version to use for connection 0=SSLv3 1=TLSv1 (defaults to SSLv3)")

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

if options.channel:
    channel = options.channel
else:
    channel = 'SYSTEM.DEF.SVRCONN'

if options.verbose:
    verbose = int(options.verbose)
else:
    verbose = 0

if options.ssl:
    ssl = int(options.ssl)
else:
    ssl = 0

if options.cipher:
    cipher = options.cipher
else:
    cipher = 'NULL-SHA'

if options.version:
    version = int(options.version)
else:
    version = 0

# Set up the MQ strings object
mq = build_packets()

# Prepare the first handshake string
send_string = mq.get_handshake(channel)

# Set up the connection to our target
if ssl == 1:
    
    if version == 0:
        ctx = SSL.Context(SSL.SSLv3_METHOD)
    else:
        ctx = SSL.Context(SSL.TLSv1_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, verify_cb) # Don't need a certificate
    ctx.set_cipher_list(cipher)
    # Uncomment these to use a client cert
    #ctx.use_privatekey_file('server.key')
    #ctx.use_certificate_file('server.crt')

    outgoing = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))

    try:
        outgoing.connect( ( target, port ) )
    except Exception:
        print 'Error, cannot connect to host', target, 'on port '+str(port)+' using SSL'
        sys.exit(0)
    else:
        print 'SSL Connection suceeded to target host', target, 'on port '+str(port)
else:
    outgoing = socket.socket ( socket.AF_INET,socket.SOCK_STREAM )
    try:
        outgoing.connect ( ( target, port ) )
    except Exception:
        print 'Error, cannot connect to host', target, 'on port '+str(port)
        sys.exit(0)
    else:
        print 'Connection suceeded to target host', target, 'on port '+str(port)

# Send the first handshake string
outgoing.send(send_string)

# Receive the response
data = read_data(outgoing,ssl)

# Print Packet Response
print "Received Handshake Response"

# Check its MQ
check_mq(data,verbose)

# Get the queue manager name 
queue_manager = check_status(data,verbose)

if queue_manager == 0:
    check_return_code(queue_manager, outgoing, "", 1)
    sys.exit(0)

# Set the flags, message size and heartbeat for the next communication
flags = string.atoi(str(binascii.hexlify(data[33:34])),16)
heartbeat = string.atol(str(binascii.hexlify(data[124:128])),16)
message_size = string.atol(str(binascii.hexlify(data[44:48])),16)

# Send the second handshake string
send_string = mq.get_handshake2(channel, flags, message_size, heartbeat)

# Send the second handshake string
outgoing.send(send_string)

# Print Packet Response
print "Received 2nd Handshake Response"

# Receive the response
data = read_data(outgoing,ssl)

flags = check_handshake(data)
if flags != "complete":
    send_string = mq.get_handshake2(channel, flags, message_size, heartbeat)
    outgoing.send(send_string)
    data = read_data(outgoing,ssl)
    check_handshake(data)

# NEED TO ADD BETTER HANDLING IF 3rd HANDSHAKE PACKET IS NEEDED

# Send the connection string
send_string = mq.get_connection(queue_manager)
outgoing.send(send_string)

# Print Packet Response
print "Received Connection Response"

# Receive the response
data = read_data(outgoing,ssl)

# Check the status of the response
check_reason(data,verbose)

send_string = mq.get_open('', 5, '', 0x20)
outgoing.send(send_string)

# Print Packet Response
print "Received Open Queue Response"

# Receive the response 
data = read_data(outgoing,ssl)

# Check the status of the response 
check_reason(data,verbose)
object_handle = string.atol(str(binascii.hexlify(data[40:44])),16)

send_string = mq.get_inquire(object_handle, 1, 0, 48, 2003)
outgoing.send(send_string)

# Print Packet Response
print "Received Inquire Response"

# Receive the response
data = read_data(outgoing,ssl)

# Check the status of the response
check_reason(data,verbose)

send_string = mq.get_open('', 1, 'SYSTEM.ADMIN.COMMAND.QUEUE', 0x10)
outgoing.send(send_string)

# Print Packet Response
print "Received Open Admin Queue Response"

# Receive the response
data = read_data(outgoing,ssl)

# Check the status of the response
check_reason(data,verbose)
object_handle_admin = string.atol(str(binascii.hexlify(data[40:44])),16)

dynamic_queue_name = get_dynamic_queue_name(data)
object_queue_manager = get_object_queue_manager_name(data)

send_string = mq.get_open('', 1, 'SYSTEM.DEFAULT.MODEL.QUEUE', 0x04)
outgoing.send(send_string)

# Print Packet Response
print "Received Open Model Queue Response"

# Receive the response
data = read_data(outgoing,ssl)

# Check the status of the response
check_reason(data,verbose)

dynamic_queue_name = get_dynamic_queue_name(data)
object_queue_manager = get_object_queue_manager_name(data)
object_handle_model = string.atol(str(binascii.hexlify(data[40:44])),16)

send_string = mq.get_inquire(object_handle, 1, 1, 48, 31)
outgoing.send(send_string)

# Print Packet Response
print "Received 2nd Inquire Response"

# Receive the response
data = read_data(outgoing,ssl)

# Check the status of the response
check_reason(data,verbose)

send_string = mq.get_pcf_inquire_qmgr(object_handle_admin, dynamic_queue_name, object_queue_manager)
outgoing.send(send_string)

# Print Packet Response
print "Received Inquire Queue Manager Response"

# Receive the response
data = read_data(outgoing,ssl)

# Check the status of the response
check_reason(data,verbose)

send_string = mq.get_get(object_handle_model, '')

loop = 0
channel_number = 1
while loop < 1:
    outgoing.send(send_string)
    time.sleep(0.5)

    # Receive the response
    data = read_data(outgoing,ssl)

    # Check the status of the response
    check_reason(data,verbose)

    # Get the data from the packet
    loop = get_queue_data_loop(data, channel_number)
    channel_number = channel_number+1

outgoing.close()
