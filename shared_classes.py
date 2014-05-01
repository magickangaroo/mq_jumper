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
# This file contains shared classes for communicating with
# Websphere MQ.
#
# Author: Martyn Ruks
# Version: 0.0.5
#
# Further information: martyn ({dot}) ruks <(at)> mwrinfosecurity {(dot)} com
#

import string
import sys
import binascii
import select

from mq_strings import *

def verify_cb(conn, cert, errnum, depth, ok):
    # Basic callback for the OpenSSL
    return ok

def check_return_code(error, outgoing, logfile, loop):
    if error == 0:
        outgoing.close()
        if loop == 0:
            sys.exit(0)
        else:
           return 1

def check_mq(data,verbose):
    if data[0:3] == 'TSH':
        if verbose == 1:
            print "MQ Detected !!"
        error = 0
    else:
        if verbose == 1:
            print "Doesn't look like MQ, response was:"
            print binascii.hexlify(data)
        error = 1
    return error

def check_status_code(status_code,verbose):
    mq_strings = static_data()
    error = mq_strings.print_status(status_code,verbose)
    return error

def check_status(data,verbose):
    if data[28:32] == '\x00\x00\x00\x08':
        status_code = data[32:36]
        #print binascii.hexlify(data[28:32])
        #print binascii.hexlify(status_code)
        error = check_status_code(status_code,verbose)
        return error
    else:
        queue_manager = data[76:124]
        if verbose == 1:
            print "Queue Manager Name: "+queue_manager
        return queue_manager

def check_reason_code(reason_code,verbose):
    mq_strings = static_data()
    mq_strings.print_reason(reason_code,verbose)

def check_completion_code(completion_code,verbose):
    mq_strings = static_data()
    error = mq_strings.print_completion(completion_code,verbose)
    return error

def check_reason(data,verbose):
    completion_code = data[32:36]
    reason_code = data[36:40]
    error = check_completion_code(completion_code,verbose)
    check_reason_code(reason_code,verbose)
    return error

def get_dynamic_queue_name(data):
    # ADD CHECKS ABOUT PACKET TYPE
    queue_name = data[56:104]
    return queue_name

def get_object_queue_manager_name(data):
    queue_manager_name = data[104:152]
    return queue_manager_name

def check_handshake(data):
    if data[35:36] != '\x00':  #or data[4:8] == '\x00\x00\x00\x82':
        print "Handshake not completed !!"
        flags = string.atoi(str(binascii.hexlify(data[33:34])),16)
        return flags
    else:
        print "Handshake Completed"
        flags = "complete"
        return flags

def read_data(socket,ssl):
    
    data=socket.recv(65535)
    return data

def check_pcf_data(data, packet_counter, param_counter):
    if data[packet_counter:packet_counter+4] == '\x00\x00\x00\x04':
        field_type = data[packet_counter+8:packet_counter+12]
        field_length = data[packet_counter+4:packet_counter+8]
        field_length = string.atoi(str(binascii.hexlify(field_length)),16)
        field_data = data[packet_counter+20:packet_counter+field_length]
        field_data = field_data.replace("\x20\x20", "")
        get_pcf_string(field_type, field_data)
        param_counter = param_counter + 1
        packet_counter = packet_counter + field_length
    elif data[packet_counter:packet_counter+4] == '\x00\x00\x00\x03':
        field_type = data[packet_counter+8:packet_counter+12]
        field_data = data[packet_counter+12:packet_counter+16]
        get_pcf_int(field_type, field_data)
        param_counter = param_counter + 1
        packet_counter = packet_counter + 16
    elif data[packet_counter:packet_counter+4] == '\x00\x00\x00\x05':
        field_type = data[packet_counter+8:packet_counter+12]
        field_count = string.atoi(str(binascii.hexlify(data[packet_counter+12:packet_counter+16])),16)
        field_data = data[packet_counter+16:packet_counter+16+field_count*4]
        field_length = string.atoi(str(binascii.hexlify(data[packet_counter+4:packet_counter+8])),16)
        get_pcf_list(field_type, field_data)
        param_counter = param_counter + 1
        packet_counter = packet_counter + field_length
    elif data[packet_counter:packet_counter+4] == '\x00\x00\x00\x06':
        field_type = data[packet_counter+8:packet_counter+12]
        field_length = string.atoi(str(binascii.hexlify(data[packet_counter+4:packet_counter+8])),16)
        list_item_number = string.atoi(str(binascii.hexlify(data[packet_counter+16:packet_counter+20])),16)
        list_item_length = string.atoi(str(binascii.hexlify(data[packet_counter+20:packet_counter+24])),16)
        field_data = data[packet_counter+24:packet_counter+24+list_item_number*list_item_length]
        get_pcf_list6(field_type, field_data, list_item_number, list_item_length)
        param_counter = param_counter + 1
        packet_counter = packet_counter + field_length
    elif data[packet_counter:packet_counter+4] == '\x00\x00\x00\x09':
        field_type = data[packet_counter+8:packet_counter+12]
        field_length = string.atoi(str(binascii.hexlify(data[packet_counter+4:packet_counter+8])),16)
        param_counter = param_counter + 1
        packet_counter = packet_counter + field_length
    counters = (packet_counter, param_counter)
    return counters 

def get_pcf_string(field_type, field_data):
    strings = static_data()
    strings.print_pcf_str(field_type, field_data)
    
def get_pcf_int(field_type, field_data):
    strings = static_data()
    strings.print_pcf_int(field_type, field_data)

def get_pcf_list(field_type, field_data):
    strings = static_data()
    strings.print_pcf_list(field_type, field_data)

def get_pcf_list6(field_type, field_data, list_item_number, list_item_length):
    strings = static_data()
    strings.print_pcf_list6(field_type, field_data, list_item_number, list_item_length)

def get_non_pcf_queue_data_loop(data, message_number):
    print "Message Number: "+str(message_number)
    data_length = data[488:492]
    data_length_int = string.atoi(str(binascii.hexlify(data_length)),16) 
    message = data[492:492+data_length_int]
    print message
    print "###################################################" 

    # Check if control bit is set
    if data[512:516] == '\x00\x00\x00\x01':
        loop = 1
    else:
        loop = 0

    return loop

def get_queue_data_loop(data, channel_number):
    print "Channel "+str(channel_number)+":"
    param_number = data[524:528]
    param_number_int = string.atoi(str(binascii.hexlify(param_number)),16)
    print "Number of parameters: "+str(param_number_int)

    param_counter = 1
    packet_counter = 528
    while param_counter <= param_number_int:
        counters = check_pcf_data(data, packet_counter, param_counter)
        packet_counter = counters[0]
        param_counter = counters[1]

    print "\n"
    # Check if control bit is set
    if data[512:516] == '\x00\x00\x00\x01':
        loop = 1
    else:
        loop = 0

    return loop

