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
# This file contains classes for manipulating packets and
# also contains constants used by the other tools.
#
# Author: Martyn Ruks
# Version: 0.0.5
#
# Further information: martyn ({dot}) ruks <(at)> mwrinfosecurity {(dot)} com
#

import string
import binascii
from struct import *

class LengthCalculation:

    def __init__(self):
        pass

    def calculate_segment_length(self, _packet):
        _length = 0
        for key1 in _packet:
            dict = _packet[key1]
            for key2 in dict:
                value = dict[key2]
                if value[2] == "B":
                    _length = _length + 1
                elif value[2] == "H":
                    _length = _length + 2
                elif value[2] == "L":
                    _length = _length + 4
                elif value[2] == "Q":
                    _length = _length + 8
                else:
                    _length = _length + len(value[0])
        return _length

class websphere_mq_packet:

    def __init__(self):
        self._tsh = {}
        self._tsh["header"] = (0x54534820, 0, "L")
        self._tsh["segment_length"] = (0x00000000, 4, "L")
        self._tsh["byte_order"] = (0x01, 8, "B")
        self._tsh["segment_type"] = (0x01, 9, "B")
        self._tsh["control_flags"] = (0x31, 10, "B")
        self._tsh["reserved"] = (0x00, 8, "B")
        self._tsh["luow_identifier"] = (0x0000000000000000, 9, "Q")
        self._tsh["encoding"] = (0x00000111, 17, "L")
        self._tsh["character_set"] = (0x0333, 21, "H")
        self._tsh["padding"] = (0x0000, 23, "H")

    # Define a method to set any field in the TSH
    def set_tsh_value(self, tsh_field_name, tsh_field_value):
        byte_data = self.get_tsh_value(tsh_field_name)
        self._tsh[tsh_field_name] = (tsh_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_tsh_value(self, tsh_field_name):
        return self._tsh[tsh_field_name]

    def rawData(self):
        data = pack('>LLBBBBQLHH', self._tsh["header"][0], self._tsh["segment_length"][0], self._tsh["byte_order"][0], self._tsh["segment_type"][0], self._tsh["control_flags"][0], self._tsh["reserved"][0], self._tsh["luow_identifier"][0], self._tsh["encoding"][0], self._tsh["character_set"][0], self._tsh["padding"][0])
        return data

class mq_initial_data:

    def __init__(self):
        self._initial_data = {}
        self._initial_data["id"] = ( 0x49442020 , 0, "L")
        self._initial_data["fap_level"] = ( 0xff, 4, "B")
        self._initial_data["flags"] = ( 0x25, 5, "B")
        self._initial_data["unknown"] = ( 0x00, 6, "B")
        self._initial_data["error_flags"] = ( 0x00, 7, "B")
        self._initial_data["unknown2"] = ( 0x0000, 8, "H")
        self._initial_data["maximum_messages"] = ( 0x0032, 10, "H")
        self._initial_data["maximum_trans_size"] = ( 0x00007ffe, 12, "L")
        self._initial_data["maximum_message_size"] = ( 0x00400000, 16, "L")
        self._initial_data["sequence_wrap"] = ( 0x3b9ac9ff, 20, "L")
        self._initial_data["channel_name"] = ( 'SYSTEM.DEF.SVRCONN  ', 24, "20s")
        self._initial_data["capability_flags"] = ( 0x01, 44, "B")
        self._initial_data["unknown3"] = ( 0x00, 45, "B")
        self._initial_data["character_set"] = ( 0x0333, 46, "H")
        self._initial_data["queue_manager"] = ( '                                                ', 48, "48s")
        self._initial_data["heartbeat"] = ( 0x00000001, 94, "L")
        self._initial_data["unknown4"] = ( 0x0000, 98, "H")

    # Define a method to set any field in the initial data 
    def set_id_value(self, id_field_name, id_field_value):
        byte_data = self.get_id_value(id_field_name)
        self._initial_data[id_field_name] = (id_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_id_value(self, id_field_name):
        return self._initial_data[id_field_name]

    def rawData(self):
        data = pack('>LBBBBHHLLL', self._initial_data["id"][0], self._initial_data["fap_level"][0], self._initial_data["flags"][0], self._initial_data["unknown"][0], self._initial_data["error_flags"][0], self._initial_data["unknown2"][0], self._initial_data["maximum_messages"][0], self._initial_data["maximum_trans_size"][0], self._initial_data["maximum_message_size"][0], self._initial_data["sequence_wrap"][0])
        data = data+self._initial_data["channel_name"][0]
        data = data+pack('>BBH', self._initial_data["capability_flags"][0], self._initial_data["unknown3"][0], self._initial_data["character_set"][0])
        data = data+self._initial_data["queue_manager"][0]+pack('>LH', self._initial_data["heartbeat"][0], self._initial_data["unknown4"][0])
        return data

# API Header Definition
class mq_api_header:

    def __init__(self):
        self._api_header = {}
        self._api_header["reply_length"] = ( 0x00000000, 0, "L")
        self._api_header["completion_code"] = ( 0x00000000, 4, "L")
        self._api_header["reason_code"] = ( 0x00000000, 8, "L")
        self._api_header["object_handle"] = ( 0x00000000, 12, "L")

    # Define a method to set any field in the initial data
    def set_api_value(self, api_field_name, api_field_value):
        byte_data = self.get_api_value(api_field_name)
        self._api_header[api_field_name] = (api_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_api_value(self, api_field_name):
        return self._api_header[api_field_name]

    def rawData(self):
        data = pack('>LLLL', self._api_header["reply_length"][0], self._api_header["completion_code"][0], self._api_header["reason_code"][0], self._api_header["object_handle"][0])
        return data

# Object Descriptor Definition
class mq_object_descriptor:

    def __init__(self):
        self._object_descriptor = {}
        self._object_descriptor["od"] = ( 0x4f442020, 0, "L")
        self._object_descriptor["version"] = ( 0x00000001, 0, "L")
        self._object_descriptor["object_type"] = ( 0x00000005, 0, "L")
        self._object_descriptor["object_name"] = ( '                                ', 0, "32s")
        self._object_descriptor["object_qm_name"] = ( '                                                ', 0, "48s")
        self._object_descriptor["dynamic_queue_name"] = ( 'AMQ.*                                           ', 0, "48s")
        self._object_descriptor["alternate_userid"] = ( 'mqm         ', 0, "12s")

    # Define a method to set any field in the initial data
    def set_od_value(self, od_field_name, od_field_value):
        byte_data = self.get_od_value(od_field_name)
        self._object_descriptor[od_field_name] = (od_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_od_value(self, od_field_name):
        return self._object_descriptor[od_field_name]

    def rawData(self):
        data = pack('>LLL', self._object_descriptor["od"][0], self._object_descriptor["version"][0], self._object_descriptor["object_type"][0])
        data = data+self._object_descriptor["object_name"][0]+self._object_descriptor["object_qm_name"][0]+self._object_descriptor["dynamic_queue_name"][0]+self._object_descriptor["alternate_userid"][0]
        return data

class mq_message_descriptor:

    def __init__(self):
        self._message_descriptor = {}
        self._message_descriptor["md"] = ( 0x4d442020, 0, "L")
        self._message_descriptor["version"] = ( 0x00000002, 0, "L")
        self._message_descriptor["report"] = ( 0x00000000, 0, "L")
        self._message_descriptor["message_type"] = ( 0x00000001, 0, "L")
        self._message_descriptor["expiry"] = ( 0x0000012c, 0, "L")
        self._message_descriptor["feedback"] = ( 0x00000000, 0, "L")
        self._message_descriptor["encoding"] = ( 0x00000111, 0, "L")
        self._message_descriptor["character_set"] = ( 0x00000333, 0, "L")
        self._message_descriptor["format"] = ( 'MQADMIN ', 0, "8s")
        self._message_descriptor["priority"] = ( 0xffffffff, 0, "L")
        self._message_descriptor["persistence"] = ( 0x00000002, 0, "L")
        self._message_descriptor["messageid"] = ( '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 0, "24s")
        self._message_descriptor["correlation_id"] = ( '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 0, "24s")
        self._message_descriptor["backout_count"] = ( 0x00000000, 0, "L")
        self._message_descriptor["reply_to_queue"] = ( '                                                ', 0, "48s")
        self._message_descriptor["reply_to_qm"] = ( '                                                ', 0, "48s")
        self._message_descriptor["userid"] = ( '            ', 0, "12s")
        self._message_descriptor["accounting_token"] = ( '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 0, "32s")
        self._message_descriptor["applicationid_data"] = ( '                                ', 0, "32s")
        self._message_descriptor["put_application_type"] = ( 0x00000000, 0, "L")
        self._message_descriptor["put_application_name"] = ( '                            ', 0, "28s")
        self._message_descriptor["put_date"] = ( 0x2020202020202020, 0, "Q")
        self._message_descriptor["put_time"] = ( 0x2020202020202020, 0, "Q")
        self._message_descriptor["application_original_data"] = ( 0x20202020, 0, "L")
        self._message_descriptor["groupid"] = ( '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 0, "24s")
        self._message_descriptor["message_sequence_number"] = ( 0x00000001, 0, "L")
        self._message_descriptor["offset"] = ( 0x00000000, 0, "L")
        self._message_descriptor["message_flags"] = ( 0x00000000, 0, "L")
        self._message_descriptor["original_length"] = ( 0xffffffff, 0, "L")

    # Define a method to set any field in the initial data
    def set_md_value(self, md_field_name, md_field_value):
        byte_data = self.get_md_value(md_field_name)
        self._message_descriptor[md_field_name] = (md_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_md_value(self, md_field_name):
        return self._message_descriptor[md_field_name]

    def rawData(self):
        data = pack('>LLLLLLLL', self._message_descriptor["md"][0], self._message_descriptor["version"][0], self._message_descriptor["report"][0], self._message_descriptor["message_type"][0], self._message_descriptor["expiry"][0], self._message_descriptor["feedback"][0], self._message_descriptor["encoding"][0], self._message_descriptor["character_set"][0])
        data = data+self._message_descriptor["format"][0]
        data = data+pack('>LL', self._message_descriptor["priority"][0], self._message_descriptor["persistence"][0])+self._message_descriptor["messageid"][0]+self._message_descriptor["correlation_id"][0]
        data = data+pack('>L', self._message_descriptor["backout_count"][0])+self._message_descriptor["reply_to_queue"][0]+self._message_descriptor["reply_to_qm"][0]+self._message_descriptor["userid"][0]+self._message_descriptor["accounting_token"][0]+self._message_descriptor["applicationid_data"][0]
        data = data+pack('>L', self._message_descriptor["put_application_type"][0])+self._message_descriptor["put_application_name"][0]
        data = data+pack('>QQL', self._message_descriptor["put_date"][0], self._message_descriptor["put_time"][0], self._message_descriptor["application_original_data"][0])+self._message_descriptor["groupid"][0]
        data = data+pack('>LLLL', self._message_descriptor["message_sequence_number"][0], self._message_descriptor["offset"][0], self._message_descriptor["message_flags"][0], self._message_descriptor["original_length"][0])
        return data

class mq_userid_data:

    def __init__(self):
        self._userid_data = {}
        self._userid_data["uid"] = ( 0x55494420, 0, "L")
        self._userid_data["userid"] = ( 'abcdefghijkl', 4, "12s")
        self._userid_data["password"] = ( 'abcdefghijkl', 16, "12s")

    # Define a method to set any field in the initial data
    def set_uid_value(self, uid_field_name, uid_field_value):
        byte_data = self.get_uid_value(uid_field_name)
        self._userid_data[uid_field_name] = (uid_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_uid_value(self, uid_field_name):
        return self._userid_data[uid_field_name]

    def rawData(self):
        data = pack('>L', self._userid_data["uid"][0])
        data = data+self._userid_data["userid"][0]+self._userid_data["password"][0]
        return data

class mq_get_message_options:

    def __init__(self):
        self._get_message = {}
        self._get_message["gmo"] = ( 0x474d4f20, 0, "L")
        self._get_message["version"] = ( 0x00000002, 4, "L")
        self._get_message["options"] = ( 0x00004005, 8, "L")
        self._get_message["wait_interval"] = ( 0x00007530, 12, "L")
        self._get_message["signal1"] = ( 0x00000000, 16, "L")
        self._get_message["signal2"] = ( 0x00000000, 20, "L")
        self._get_message["resolved_queue_name"] = ( '                                                ', 32, "48s")
        self._get_message["match_options"] = ( 0x00000003, 68, "L")
        self._get_message["group_status"] = ( 0x20, 72, "B")
        self._get_message["segment_status"] = ( 0x20, 73, "B")
        self._get_message["segmentation"] = ( 0x20, 74, "B")
        self._get_message["reserved"] = ( 0x00, 75, "B")

    # Define a method to set any field in the initial data
    def set_gmo_value(self, gmo_field_name, gmo_field_value):
        byte_data = self.get_gmo_value(gmo_field_name)
        self._get_message[gmo_field_name] = (gmo_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_gmo_value(self, gmo_field_name):
        return self._get_message[gmo_field_name]

    def rawData(self):
        data = pack('>LLLLLL', self._get_message["gmo"][0], self._get_message["version"][0], self._get_message["options"][0], self._get_message["wait_interval"][0], self._get_message["signal1"][0], self._get_message["signal2"][0])
        data = data+self._get_message["resolved_queue_name"][0]
        data = data+pack('>LBBBB', self._get_message["match_options"][0], self._get_message["group_status"][0], self._get_message["segment_status"][0], self._get_message["segmentation"][0], self._get_message["reserved"][0])
        return data

class mq_put_message_options:

    def __init__(self):
        self._put_message = {}
        self._put_message["pmo"] = ( 0x504d4f20, 0, "L")
        self._put_message["version"] = ( 0x00000001, 4, "L")
        self._put_message["options"] = ( 0x00000004, 8, "L")
        self._put_message["timeout"] = ( 0xffffffff, 12, "L")
        self._put_message["context"] = ( 0x00000000, 16, "L")
        self._put_message["known_dest_count"] = ( 0x00000000, 20, "L")
        self._put_message["unknown_dest_count"] = ( 0x00000000, 24, "L")
        self._put_message["invalid_dest_count"] = ( 0x00000001, 28, "L")
        self._put_message["resolved_queue_name"] = ( '                                                ', 32, "48s")
        self._put_message["resolved_queue_manager_name"] = ( '                                                ', 76, "48s")

    # Define a method to set any field in the initial data
    def set_pmo_value(self, pmo_field_name, pmo_field_value):
        byte_data = self.get_pmo_value(pmo_field_name)
        self._put_message[pmo_field_name] = (pmo_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_pmo_value(self, pmo_field_name):
        return self._put_message[pmo_field_name]

    def rawData(self):
        data = pack('>LLLLLLLL', self._put_message["pmo"][0], self._put_message["version"][0], self._put_message["options"][0], self._put_message["timeout"][0], self._put_message["context"][0], self._put_message["known_dest_count"][0], self._put_message["unknown_dest_count"][0], self._put_message["invalid_dest_count"][0])
        data = data+self._put_message["resolved_queue_name"][0]+self._put_message["resolved_queue_manager_name"][0]
        return data


class mq_conn:

    def __init__(self):
        self._mq_conn = {}
        self._mq_conn["queue_manager"] = ( '                                                ' , 0, "48s")
        self._mq_conn["application_name"] = ( 'Websphere MQ Client for Java', 48, "28s")
        self._mq_conn["application_type"] = ( 0x0000001c, 76, "L")
        self._mq_conn["accounting_token"] = ( '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 80, "32s")
        self._mq_conn["version"] = ( 0x00000001, 112, "L")
        self._mq_conn["options"] = ( 0x00000000, 116, "L")

    # Define a method to set any field in the initial data
    def set_conn_value(self, conn_field_name, conn_field_value):
        byte_data = self.get_conn_value(conn_field_name)
        self._mq_conn[conn_field_name] = (conn_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_conn_value(self, conn_field_name):
        return self._mq_conn[conn_field_name]

    def rawData(self):
        data = self._mq_conn["queue_manager"][0]+self._mq_conn["application_name"][0]
        data = data+pack('>L', self._mq_conn["application_type"][0])+self._mq_conn["accounting_token"][0]+pack('>LL' , self._mq_conn["version"][0], self._mq_conn["options"][0])
        return data

class mq_open:

    def __init__(self):
        self._mq_open = {}
        self._mq_open["options"] = ( 0x00000020 , 0, "L")

    # Define a method to set any field
    def set_open_value(self, open_field_name, open_field_value):
        byte_data = self.get_open_value(open_field_name)
        self._mq_open[open_field_name] = (open_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_open_value(self, open_field_name):
        return self._mq_open[open_field_name]

    def rawData(self):
        data = pack('>L', self._mq_open["options"][0])
        return data

class mq_put:

    def __init__(self):
        self._mq_put = {}
        self._mq_put["data_length"] = ( 0x00000020 , 0, "L")

    # Define a method to set any field
    def set_put_value(self, put_field_name, put_field_value):
        byte_data = self.get_put_value(put_field_name)
        self._mq_put[put_field_name] = (put_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_put_value(self, put_field_name):
        return self._mq_put[put_field_name]

    def rawData(self):
        data = pack('>L', self._mq_put["data_length"][0])
        return data


class mq_inquire:

    def __init__(self):
        self._mq_inquire = {}
        self._mq_inquire["selector_count"] = ( 0x00000001 , 0, "L")
        self._mq_inquire["integer_count"] = ( 0x00000000 , 0, "L")
        self._mq_inquire["character_length"] = ( 0x00000030 , 0, "L")
        self._mq_inquire["selector"] = ( 0x000007d3 , 0, "L")

    # Define a method to set any field in the initial data
    def set_inquire_value(self, inquire_field_name, inquire_field_value):
        byte_data = self.get_inquire_value(inquire_field_name)
        self._mq_inquire[inquire_field_name] = (inquire_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_inquire_value(self, inquire_field_name):
        return self._mq_inquire[inquire_field_name]

    def rawData(self):
        data = pack('>LLLL', self._mq_inquire["selector_count"][0], self._mq_inquire["integer_count"][0], self._mq_inquire["character_length"][0], self._mq_inquire["selector"][0])
        return data

class mq_pcf:

    def __init__(self):
        self._mq_pcf = {}
        self._mq_pcf["type"] = ( 0x00000001 , 0, "L")
        self._mq_pcf["length"] = ( 0x00000024 , 0, "L")
        self._mq_pcf["version"] = ( 0x00000001 , 0, "L")
        self._mq_pcf["command"] = ( 0x00000019 , 0, "L")
        self._mq_pcf["message_sequence_number"] = ( 0x00000001 , 0, "L")
        self._mq_pcf["control"] = ( 0x00000001 , 0, "L")
        self._mq_pcf["completion_code"] = ( 0x00000000 , 0, "L")
        self._mq_pcf["reason_code"] = ( 0x00000000 , 0, "L")
        self._mq_pcf["parameter_count"] = ( 0x00000002 , 0, "L")
        self._mq_pcf["data"] = ( 'abcdefghij' , 0, "10s")

    # Define a method to set any field in the initial data
    def set_pcf_value(self, pcf_field_name, pcf_field_value):
        byte_data = self.get_pcf_value(pcf_field_name)
        self._mq_pcf[pcf_field_name] = (pcf_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_pcf_value(self, pcf_field_name):
        return self._mq_pcf[pcf_field_name]

    def rawData(self):
        data = pack('>LLLLLLLLL', self._mq_pcf["type"][0], self._mq_pcf["length"][0], self._mq_pcf["version"][0], self._mq_pcf["command"][0], self._mq_pcf["message_sequence_number"][0], self._mq_pcf["control"][0], self._mq_pcf["completion_code"][0], self._mq_pcf["reason_code"][0], self._mq_pcf["parameter_count"][0])+self._mq_pcf["data"][0]
        return data

class pcf_integer:

    def __init__(self):
        self._mq_pcf_int = {}
        self._mq_pcf_int["type"] = ( 0x00000003 , 0, "L")
        self._mq_pcf_int["length"] = ( 0x00000010 , 0, "L")
        self._mq_pcf_int["code"] = ( 0x00000001 , 0, "L")
        self._mq_pcf_int["data"] = ( 0x00000001 , 0, "L")

    # Define a method to set any field
    def set_pcf_int_value(self, pcf_int_field_name, pcf_int_field_value):
        byte_data = self.get_pcf_int_value(pcf_int_field_name)
        self._mq_pcf_int[pcf_int_field_name] = (pcf_int_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_pcf_int_value(self, pcf_int_field_name):
        return self._mq_pcf_int[pcf_int_field_name]

    def rawData(self):
        data = pack('>LLLL', self._mq_pcf_int["type"][0], self._mq_pcf_int["length"][0], self._mq_pcf_int["code"][0], self._mq_pcf_int["data"][0])
        return data


class pcf_string:

    def __init__(self):
        self._mq_pcf_str = {}
        self._mq_pcf_str["type"] = ( 0x00000004 , 0, "L")
        self._mq_pcf_str["length"] = ( 0x00000018 , 0, "L")
        self._mq_pcf_str["code"] = ( 0x00000dad , 0, "L")
        self._mq_pcf_str["encoding"] = ( 0x00000333 , 0, "L")
        self._mq_pcf_str["string_length"] = ( 0x00000004 , 0, "L")
        self._mq_pcf_str["data"] = ( 'ABCD', 0, "4s")

    # Define a method to set any field
    def set_pcf_str_value(self, pcf_str_field_name, pcf_str_field_value):
        byte_data = self.get_pcf_str_value(pcf_str_field_name)
        self._mq_pcf_str[pcf_str_field_name] = (pcf_str_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_pcf_str_value(self, pcf_str_field_name):
        return self._mq_pcf_str[pcf_str_field_name]

    def rawData(self):
        data = pack('>LLLLL', self._mq_pcf_str["type"][0], self._mq_pcf_str["length"][0], self._mq_pcf_str["code"][0], self._mq_pcf_str["encoding"][0], self._mq_pcf_str["string_length"][0])+self._mq_pcf_str["data"][0]
        return data

class pcf_string_filter:

    def __init__(self):
        self._mq_pcf_str_filter = {}
        self._mq_pcf_str_filter["type"] = ( 0x0000000e , 0, "L")
        self._mq_pcf_str_filter["length"] = ( 0x00000018 , 0, "L")
        self._mq_pcf_str_filter["code"] = ( 0x00000dad , 0, "L")
        self._mq_pcf_str_filter["operator"] = ( 0x00000012 , 0, "L")
        self._mq_pcf_str_filter["encoding"] = ( 0x000004b8 , 0, "L")
        self._mq_pcf_str_filter["string_length"] = ( 0x00000004 , 0, "L")
        self._mq_pcf_str_filter["data"] = ( 'ABCD', 0, "4s")

    # Define a method to set any field
    def set_pcf_str_filter_value(self, pcf_str_filter_field_name, pcf_str_filter_field_value):
        byte_data = self.get_pcf_str_filter_value(pcf_str_filter_field_name)
        self._mq_pcf_str_filter[pcf_str_filter_field_name] = (pcf_str_filter_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_pcf_str_filter_value(self, pcf_str_filter_field_name):
        return self._mq_pcf_str_filter[pcf_str_filter_field_name]

    def rawData(self):
        data = pack('>LLLLLL', self._mq_pcf_str_filter["type"][0], self._mq_pcf_str_filter["length"][0], self._mq_pcf_str_filter["code"][0], self._mq_pcf_str_filter["operator"][0], self._mq_pcf_str_filter["encoding"][0], self._mq_pcf_str_filter["string_length"][0])+self._mq_pcf_str_filter["data"][0]
        return data

class pcf_int_list:

    def __init__(self):
        self._mq_pcf_int_list = {}
        self._mq_pcf_int_list["type"] = ( 0x00000005, 0, "L")
        self._mq_pcf_int_list["length"] = ( 0x00000014, 4, "L")
        self._mq_pcf_int_list["code"] = ( 0x00000445, 8, "L")
        self._mq_pcf_int_list["count"] = ( 0x00000001, 12, "L")
        self._mq_pcf_int_list["data"] = ( 'ABCD', 16, "4s")

    # Define a method to set any field
    def set_pcf_int_list_value(self, pcf_int_list_field_name, pcf_int_list_field_value):
        byte_data = self.get_pcf_int_list_value(pcf_int_list_field_name)
        self._mq_pcf_int_list[pcf_int_list_field_name] = (pcf_int_list_field_value, byte_data[1], byte_data[2])

    # Define a method to get any field in the packet
    def get_pcf_int_list_value(self, pcf_int_list_field_name):
        return self._mq_pcf_int_list[pcf_int_list_field_name]

    def rawData(self):
        data = pack('>LLLL', self._mq_pcf_int_list["type"][0], self._mq_pcf_int_list["length"][0], self._mq_pcf_int_list["code"][0], self._mq_pcf_int_list["count"][0])+self._mq_pcf_int_list["data"][0]
        return data

class mq_trigger_data:
        
    def __init__(self):
        self._mq_trigger_data = {}
        self._mq_trigger_data["header1"] = ( 'TM  ', 0, "4s")
        self._mq_trigger_data["header2"] = ( 0x01000000, 4, "L")
        self._mq_trigger_data["queue_name"] = ( 'QUEUENAME                                       ', 8, "48s")
        self._mq_trigger_data["process_name"] = ( '                                                                                                                ' , 56, "112s")
        self._mq_trigger_data["header3"] = ( 0x0b000000, 168, "L")
        self._mq_trigger_data["command"] = ( 'COMMAND         COMMAND         COMMAND         COMMAND         COMMAND         COMMAND         COMMAND         COMMAND         COMMAND         COMMAND         COMMAND         COMMAND         COMMAND         COMMAND         COMMAND         COMMAND         ', 172, "256s")
        self._mq_trigger_data["environment_data"] = ( '                                                                                                                                ', 428, "128s")
        self._mq_trigger_data["user_data"] = ( '                                                                                                                                ', 556, "128s")

    # Define a method to set any field
    def set_trigger_data_value(self, trigger_data_field_name, trigger_data_field_value):
        byte_data = self.get_trigger_data_value(trigger_data_field_name)
        self._mq_trigger_data[trigger_data_field_name] = (trigger_data_field_value, byte_data[1], byte_data[2])
        
    # Define a method to get any field in the packet
    def get_trigger_data_value(self, trigger_data_field_name):
        return self._mq_trigger_data[trigger_data_field_name]

    def rawData(self):
        data = self._mq_trigger_data["header1"][0]+pack('>L', self._mq_trigger_data["header2"][0])+self._mq_trigger_data["queue_name"][0]+self._mq_trigger_data["process_name"][0]+pack('>L', self._mq_trigger_data["header3"][0])+self._mq_trigger_data["command"][0]+self._mq_trigger_data["environment_data"][0]+self._mq_trigger_data["user_data"][0]
        return data

class build_packets:

    def __init__(self):
        pass

    def get_username(self, user):
        if user == '':
            username = 12*'\x20'
        else:
            username = user+(12-len(user))*'\x20'
        return username

    def get_process_name(self, process):
        if process == '':
            process_name = 112*'\x20'
        else:
            process_name = process+(112-len(process))*'\x20'
        return process_name

    def get_command_name(self, command):
        if command == '':
            command_name = '\x0b\x00\x00\x00'+256*'\x20'
        else:
            command_name = command+(256-len(command))*'\x20'
        return command_name

    def get_channel_name(self, channel):
        if channel == '':
            channel_name = 20*'\x20'
        else:
            channel_name = channel+(20-len(channel))*'\x20'
        return channel_name

    def get_queue_manager_name(self, queue_manager):
        if queue_manager == '':
            queue_manager_name = 48*'\x20'
        else:
            queue_manager_name = queue_manager+(48-len(queue_manager))*'\x20'
        return queue_manager_name

    def get_object_name(self, object):
        if object == '':
            object_name = 48*'\x20'
        else:
            object_name = object+(48-len(object))*'\x20'
        return object_name

    def get_queue_name(self, queue):
        if queue == '':
            queue_name = 48*'\x20'
        else:
            queue_name = queue+(48-len(queue))*'\x20'
        return queue_name

    def get_handshake(self, channel):
        channel_name = self.get_channel_name(channel)
        tsh = websphere_mq_packet()
        initial_data = mq_initial_data()
        initial_data.set_id_value("channel_name", channel_name)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["initial_data"] = initial_data._initial_data
        lengths = LengthCalculation()
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        handshake_string = tsh.rawData()+initial_data.rawData()
        return handshake_string

    def get_handshake2(self, channel, flags, message_size, heartbeat):
        # Correctly set up the channel name string
        channel_name = self.get_channel_name(channel)
        tsh = websphere_mq_packet()
        initial_data = mq_initial_data()
        initial_data.set_id_value("channel_name", channel_name)
        initial_data.set_id_value("flags", flags)
        initial_data.set_id_value("fap_level", 0x06)
        initial_data.set_id_value("heartbeat", 0x012c)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["initial_data"] = initial_data._initial_data
        lengths = LengthCalculation()
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        handshake_string = tsh.rawData()+initial_data.rawData()
        return handshake_string

    def get_userid(self, channel, userid, password):
        # Correctly set up the channel name string
        channel_name = self.get_channel_name(channel)
        tsh = websphere_mq_packet()
        tsh.set_tsh_value("control_flags", 0x30)
        tsh.set_tsh_value("segment_type", 0x08)
        userid_data = mq_userid_data()
        userid_data.set_uid_value("userid", userid)
        userid_data.set_uid_value("password", password)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["userid_data"] = userid_data._userid_data
        lengths = LengthCalculation()
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        handshake_string = tsh.rawData()+userid_data.rawData()
        return handshake_string

    def get_connection(self, queue_manager):
        queue_manager_name = self.get_queue_manager_name(queue_manager)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        conn = mq_conn()
        tsh.set_tsh_value("segment_type", 0x81)
        tsh.set_tsh_value("control_flags", 0x30)
        conn.set_conn_value("queue_manager", queue_manager)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_conn"] = conn._mq_conn
        lengths = LengthCalculation()
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        connection_string = tsh.rawData()+api.rawData()+conn.rawData()
        return connection_string

    def get_open(self, object, object_type, object_name, options):
        object_name = self.get_object_name(object_name)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        od = mq_object_descriptor()
        open = mq_open()
        tsh.set_tsh_value("segment_type", 0x83)
        tsh.set_tsh_value("control_flags", 0x30)
        od.set_od_value("object_type", object_type)
        od.set_od_value("object_name", object_name)
        open.set_open_value("options", options)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_object_descriptor"] = od._object_descriptor
        whole_packet["mq_open"] = open._mq_open
        lengths = LengthCalculation()
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        open_string = tsh.rawData()+api.rawData()+od.rawData()+open.rawData()
        return open_string

    def get_put(self, object_handle, data, user):
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        userid = self.get_username(user)
        userid = userid[0:12]
        md.set_md_value("userid", userid)
        md.set_md_value("message_type", 0x00000008)
        md.set_md_value("format", 'MQSTR   ')
        md.set_md_value("persistence", 0x00000001)
        md.set_md_value("priority", 0x00000004)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        lengths = LengthCalculation()
        data_length = len(data)
        packet_length = lengths.calculate_segment_length(whole_packet)+data_length
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        put.set_put_value("data_length", data_length)
        put_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+data
        return put_string

    def get_init_put(self, object_handle, command):
        mq_trigger = mq_trigger_data()
        command_name = self.get_command_name(command)
        mq_trigger.set_trigger_data_value("command", command_name)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("message_type", 0x00000008)
        md.set_md_value("format", 'MQTRIG  ')
        md.set_md_value("persistence", 0x00000001)
        md.set_md_value("priority", 0x00000004)
        md.set_md_value("encoding", 0x00000222)
        md.set_md_value("character_set", 0x000001b5)
        lengths = LengthCalculation()
        whole_packet = {}
        whole_packet["trigger_data"] = mq_trigger._mq_trigger_data
        data_length = lengths.calculate_segment_length(whole_packet)
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        put.set_put_value("data_length", data_length)
        put_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+mq_trigger.rawData()
        return put_string

    def get_inquire(self, object_handle, selector_count, integer_count, character_length, selector):
        #object_name = self.get_object_name(object)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        inquire = mq_inquire()
        tsh.set_tsh_value("segment_type", 0x89)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        inquire.set_inquire_value("selector_count", selector_count)
        inquire.set_inquire_value("integer_count", integer_count)
        inquire.set_inquire_value("character_length", character_length)
        inquire.set_inquire_value("selector", selector)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_inquire"] = inquire._mq_inquire
        lengths = LengthCalculation()
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        inquire_string = tsh.rawData()+api.rawData()+inquire.rawData()
        return inquire_string

    def get_pcf_inquire_channel(self, object_handle, model_queue, object_queue_manager):
        # Construct the PCF data
        pcf = mq_pcf()
        pcf_channel_type = pcf_integer()
        pcf_channel_type.set_pcf_int_value("code", 0x000005e7)
        pcf_channel_type.set_pcf_int_value("data", 0x00000005)
        pcf_channel_name = pcf_string()
        pcf_channel_name.set_pcf_str_value("data", '*   ')
        pcf_data = pcf_channel_name.rawData()+pcf_channel_type.rawData()
        pcf.set_pcf_value("data", pcf_data)
        lengths = LengthCalculation()
        pcf_packet = {}
        pcf_packet["pcf_packet"] = pcf._mq_pcf
        pcf_length = lengths.calculate_segment_length(pcf_packet)
        model_queue_name = self.get_queue_name(model_queue)
        object_queue_manager_name = self.get_queue_manager_name(object_queue_manager) 
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("reply_to_queue", model_queue_name)
        md.set_md_value("reply_to_qm", object_queue_manager_name)
        put.set_put_value("data_length", pcf_length)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        whole_packet["pcf"] = pcf._mq_pcf
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        inquire_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+pcf.rawData()
        return inquire_string

    def get_pcf_inquire_queue(self, object_handle, model_queue, object_queue_manager):
        # Construct the PCF data
        pcf = mq_pcf()
        pcf_channel_type = pcf_integer()
        pcf_channel_type.set_pcf_int_value("code", 0x00000014)
        pcf_channel_type.set_pcf_int_value("data", 0x000003e9)
        pcf_channel_name = pcf_string()
        pcf_channel_name.set_pcf_str_value("code", 0x000007e0)
        pcf_channel_name.set_pcf_str_value("data", '*   ')
        pcf_data = pcf_channel_name.rawData()+pcf_channel_type.rawData()
        pcf.set_pcf_value("data", pcf_data)
        lengths = LengthCalculation()
        pcf_packet = {}
        pcf.set_pcf_value("command", 0x0000000d)
        pcf.set_pcf_value("parameter_count", 0x00000002)
        pcf_packet["pcf_packet"] = pcf._mq_pcf
        pcf_length = lengths.calculate_segment_length(pcf_packet)
        model_queue_name = self.get_queue_name(model_queue)
        object_queue_manager_name = self.get_queue_manager_name(object_queue_manager)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("reply_to_queue", model_queue_name)
        md.set_md_value("reply_to_qm", object_queue_manager_name)
        put.set_put_value("data_length", pcf_length)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        whole_packet["pcf"] = pcf._mq_pcf
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        inquire_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+pcf.rawData()
        return inquire_string

    def get_pcf_inquire_queue_status(self, object_handle, model_queue, object_queue_manager, status_type):
        # Construct the PCF data
        pcf = mq_pcf()
        pcf_status_list = pcf_int_list()
        pcf_status_list.set_pcf_int_list_value("code", 0x00000402)
        pcf_status_list.set_pcf_int_list_value("data", '\x00\x00\x03\xf1')
        pcf_status_type = pcf_integer()
        pcf_status_type.set_pcf_int_value("code", 0x0000044f)
        if status_type == 1:
            pcf_status_type.set_pcf_int_value("data", 0x00000450)
        else:
            pcf_status_type.set_pcf_int_value("data", 0x00000451)
        pcf_queue_name = pcf_string()
        pcf_queue_name.set_pcf_str_value("code", 0x000007e0)
        pcf_queue_name.set_pcf_str_value("data", '*   ')
        pcf_data = pcf_queue_name.rawData()+pcf_status_type.rawData()+pcf_status_list.rawData()
        pcf.set_pcf_value("data", pcf_data)
        lengths = LengthCalculation()
        pcf_packet = {}
        pcf.set_pcf_value("command", 0x00000029)
        pcf.set_pcf_value("parameter_count", 0x00000003)
        pcf_packet["pcf_packet"] = pcf._mq_pcf
        pcf_length = lengths.calculate_segment_length(pcf_packet)
        model_queue_name = self.get_queue_name(model_queue)
        object_queue_manager_name = self.get_queue_manager_name(object_queue_manager)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("reply_to_queue", model_queue_name)
        md.set_md_value("reply_to_qm", object_queue_manager_name)
        put.set_put_value("data_length", pcf_length)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        whole_packet["pcf"] = pcf._mq_pcf
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        inquire_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+pcf.rawData()
        return inquire_string

    def get_pcf_inquire_qmgr(self, object_handle, model_queue, object_queue_manager):
        # Construct the PCF data
        pcf = mq_pcf()
        pcf_data = ''
        pcf.set_pcf_value("data", pcf_data)
        lengths = LengthCalculation()
        pcf_packet = {}
        pcf.set_pcf_value("command", 0x00000002)
        pcf.set_pcf_value("parameter_count", 0x00000000)
        pcf_packet["pcf_packet"] = pcf._mq_pcf
        pcf_length = lengths.calculate_segment_length(pcf_packet)
        model_queue_name = self.get_queue_name(model_queue)
        object_queue_manager_name = self.get_queue_manager_name(object_queue_manager)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("reply_to_queue", model_queue_name)
        md.set_md_value("reply_to_qm", object_queue_manager_name)
        put.set_put_value("data_length", pcf_length)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        whole_packet["pcf"] = pcf._mq_pcf
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        inquire_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+pcf.rawData()
        return inquire_string

    def get_pcf_inquire_auth_info(self, object_handle, model_queue, object_queue_manager):
        # Construct the PCF data
        pcf = mq_pcf()
        pcf_authinfo_name = pcf_string()
        pcf_authinfo_name.set_pcf_str_value("data", '*   ')
        pcf_authinfo_name.set_pcf_str_value("code", 0x000007fd)
        pcf_authinfo_name.set_pcf_str_value("encoding", 0x000004b8)
        pcf_data = pcf_authinfo_name.rawData()
        pcf.set_pcf_value("data", pcf_data)
        lengths = LengthCalculation()
        pcf_packet = {}
        pcf.set_pcf_value("command", 0x00000053)
        pcf.set_pcf_value("parameter_count", 0x00000001)
        pcf_packet["pcf_packet"] = pcf._mq_pcf
        pcf_length = lengths.calculate_segment_length(pcf_packet)
        model_queue_name = self.get_queue_name(model_queue)
        object_queue_manager_name = self.get_queue_manager_name(object_queue_manager)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("reply_to_queue", model_queue_name)
        md.set_md_value("reply_to_qm", object_queue_manager_name)
        put.set_put_value("data_length", pcf_length)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        whole_packet["pcf"] = pcf._mq_pcf
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        inquire_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+pcf.rawData()
        return inquire_string

    def get_pcf_inquire_service(self, object_handle, model_queue, object_queue_manager):
        # Construct the PCF data
        pcf = mq_pcf()
        pcf_service_name = pcf_string()
        pcf_service_name.set_pcf_str_value("data", '*   ')
        pcf_service_name.set_pcf_str_value("code", 0x0000081d)
        pcf_service_name.set_pcf_str_value("encoding", 0x000004b8)
        pcf_data = pcf_service_name.rawData()
        pcf.set_pcf_value("data", pcf_data)
        lengths = LengthCalculation()
        pcf_packet = {}
        pcf_packet["pcf_packet"] = pcf._mq_pcf
        pcf.set_pcf_value("command", 0x00000099)
        pcf.set_pcf_value("parameter_count", 0x00000001)
        pcf_length = lengths.calculate_segment_length(pcf_packet)
        model_queue_name = self.get_queue_name(model_queue)
        object_queue_manager_name = self.get_queue_manager_name(object_queue_manager)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("reply_to_queue", model_queue_name)
        md.set_md_value("reply_to_qm", object_queue_manager_name)
        put.set_put_value("data_length", pcf_length)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        whole_packet["pcf"] = pcf._mq_pcf
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        inquire_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+pcf.rawData()
        return inquire_string

    def get_pcf_create_q_with_trigger(self, object_handle, model_queue, object_queue_manager):
        # Construct the PCF data
        lengths = LengthCalculation()
        pcf = mq_pcf()
        pcf_trigger_control = pcf_integer()
        pcf_trigger_control.set_pcf_int_value("code", 0x00000018)
        pcf_trigger_control.set_pcf_int_value("data", 0x00000001)
        pcf_trigger_type = pcf_integer()
        pcf_trigger_type.set_pcf_int_value("code", 0x0000001c)
        pcf_trigger_type.set_pcf_int_value("data", 0x00000002)
        pcf_trigger_msg_priority = pcf_integer()
        pcf_trigger_msg_priority.set_pcf_int_value("code", 0x0000001a)
        pcf_trigger_msg_priority.set_pcf_int_value("data", 0x00000000)
        pcf_trigger_depth = pcf_integer()
        pcf_trigger_depth.set_pcf_int_value("code", 0x0000001d)
        pcf_trigger_depth.set_pcf_int_value("data", 0x00000001)
        pcf_queue_type = pcf_integer()
        pcf_queue_type.set_pcf_int_value("code", 0x00000014)
        pcf_queue_type.set_pcf_int_value("data", 0x00000001)
        pcf_queue_name = pcf_string()
        pcf_queue_name.set_pcf_str_value("data", 'MWRI.TEST.QQ        ')
        pcf_queue_name.set_pcf_str_value("code", 0x000007e0)
        pcf_queue_name.set_pcf_str_value("encoding", 0x00000000)
        pcf_queue_name_length = len(pcf_queue_name.get_pcf_str_value("data")[0])
        pcf_queue_name.set_pcf_str_value("string_length", pcf_queue_name_length)
        pcf_queue_name.set_pcf_str_value("length", pcf_queue_name_length+20)
        pcf_init_queue_name = pcf_string()
        pcf_init_queue_name.set_pcf_str_value("data", 'SYSTEM.DEFAULT.INITIATION.QUEUE ')
        pcf_init_queue_name.set_pcf_str_value("code", 0x000007d8)
        pcf_init_queue_name.set_pcf_str_value("encoding", 0x00000000)
        pcf_init_queue_name_length = len(pcf_init_queue_name.get_pcf_str_value("data")[0])
        pcf_init_queue_name.set_pcf_str_value("string_length", pcf_init_queue_name_length)
        pcf_init_queue_name.set_pcf_str_value("length", pcf_init_queue_name_length+20)
        pcf_process_name = pcf_string()
        pcf_process_name.set_pcf_str_value("data", 'serv                                            ')
        pcf_process_name.set_pcf_str_value("code", 0x000007dc)
        pcf_process_name.set_pcf_str_value("encoding", 0x00000000)
        pcf_process_name_length = len(pcf_process_name.get_pcf_str_value("data")[0])
        pcf_process_name.set_pcf_str_value("string_length", pcf_process_name_length)
        pcf_process_name.set_pcf_str_value("length", pcf_process_name_length+20)
        pcf_data = pcf_queue_name.rawData()+pcf_queue_type.rawData()+pcf_process_name.rawData()+pcf_trigger_control.rawData()+pcf_trigger_type.rawData()+pcf_trigger_msg_priority.rawData()+pcf_trigger_depth.rawData()+pcf_init_queue_name.rawData()
        pcf.set_pcf_value("data", pcf_data)
        pcf_packet = {}
        pcf_packet["pcf_packet"] = pcf._mq_pcf
        pcf.set_pcf_value("command", 0x0000000b)
        pcf.set_pcf_value("parameter_count", 0x00000008)
        pcf_length = lengths.calculate_segment_length(pcf_packet)
        model_queue_name = self.get_queue_name(model_queue)
        object_queue_manager_name = self.get_queue_manager_name(object_queue_manager)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("reply_to_queue", model_queue_name)
        md.set_md_value("reply_to_qm", object_queue_manager_name)
        put.set_put_value("data_length", pcf_length)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        whole_packet["pcf"] = pcf._mq_pcf
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        create_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+pcf.rawData()
        return create_string

    def get_pcf_create_service(self, object_handle, model_queue, object_queue_manager, command, args):
        # Construct the PCF data
        lengths = LengthCalculation()
        pcf = mq_pcf()
        pcf_service_type = pcf_integer()
        pcf_service_type.set_pcf_int_value("code", 0x0000008b)
        pcf_service_type.set_pcf_int_value("data", 0x00000000)
        pcf_service_command = pcf_string()
        pcf_service_command.set_pcf_str_value("data", '')
        pcf_service_command.set_pcf_str_value("code", 0x0000081f)
        pcf_service_command.set_pcf_str_value("encoding", 0x000004b8)
        pcf_service_command_length = len(pcf_service_command.get_pcf_str_value("data")[0])
        pcf_service_command.set_pcf_str_value("string_length", pcf_service_command_length)
        pcf_service_command.set_pcf_str_value("length", pcf_service_command_length+20)
        pcf_service_args = pcf_string()
        pcf_service_args.set_pcf_str_value("data", '')
        pcf_service_args.set_pcf_str_value("code", 0x00000820)
        pcf_service_args.set_pcf_str_value("encoding", 0x000004b8)
        pcf_service_args_length = len(pcf_service_args.get_pcf_str_value("data")[0])         
        pcf_service_args.set_pcf_str_value("string_length", pcf_service_args_length)
        pcf_service_args.set_pcf_str_value("length", pcf_service_args_length+20)
        pcf_service_name = pcf_string()
        pcf_service_name.set_pcf_str_value("data", 'hack')
        pcf_service_name.set_pcf_str_value("code", 0x00000c37)
        pcf_service_name.set_pcf_str_value("encoding", 0x000004b8)
        pcf_service_name_length = len(pcf_service_name.get_pcf_str_value("data")[0])
        pcf_service_name.set_pcf_str_value("string_length", pcf_service_name_length)
        pcf_service_name.set_pcf_str_value("length", pcf_service_name_length+20)
        pcf_service_template = pcf_string()
        pcf_service_template.set_pcf_str_value("data", 'SYSTEM.DEFAULT.SERVICE  ')
        pcf_service_template.set_pcf_str_value("code", 0x00000c36)
        pcf_service_template.set_pcf_str_value("encoding", 0x000004b8)
        pcf_service_template_length = len(pcf_service_template.get_pcf_str_value("data")[0])
        pcf_service_template.set_pcf_str_value("string_length", pcf_service_template_length)
        pcf_service_template.set_pcf_str_value("length", pcf_service_template_length+20)
        pcf_data = pcf_service_template.rawData()+pcf_service_name.rawData()+pcf_service_type.rawData()+pcf_service_args.rawData()+pcf_service_command.rawData()
        pcf.set_pcf_value("data", pcf_data)
        pcf_packet = {}
        pcf_packet["pcf_packet"] = pcf._mq_pcf
        pcf.set_pcf_value("command", 0x00000096)
        pcf.set_pcf_value("parameter_count", 0x00000005)
        pcf_length = lengths.calculate_segment_length(pcf_packet)
        model_queue_name = self.get_queue_name(model_queue)
        object_queue_manager_name = self.get_queue_manager_name(object_queue_manager)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("reply_to_queue", model_queue_name)
        md.set_md_value("reply_to_qm", object_queue_manager_name)
        put.set_put_value("data_length", pcf_length)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        whole_packet["pcf"] = pcf._mq_pcf
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        create_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+pcf.rawData()
        return create_string

    def get_pcf_create_process(self, object_handle, model_queue, object_queue_manager, command, args):
        # Construct the PCF data
        lengths = LengthCalculation()
        pcf = mq_pcf()
        pcf_process_command = pcf_string()
        pcf_process_command.set_pcf_str_value("data", '')
        pcf_process_command.set_pcf_str_value("code", 0x000007d1)
        pcf_process_command.set_pcf_str_value("encoding", 0x000004b8)
        pcf_process_command_length = len(pcf_process_command.get_pcf_str_value("data")[0])
        pcf_process_command.set_pcf_str_value("string_length", pcf_process_command_length)
        pcf_process_command.set_pcf_str_value("length", pcf_process_command_length+20)
        pcf_process_name = pcf_string()
        pcf_process_name.set_pcf_str_value("data", 'hack')
        pcf_process_name.set_pcf_str_value("code", 0x000007dc)
        pcf_process_name.set_pcf_str_value("encoding", 0x000004b8)
        pcf_process_name_length = len(pcf_process_name.get_pcf_str_value("data")[0])
        pcf_process_name.set_pcf_str_value("string_length", pcf_process_name_length)
        pcf_process_name.set_pcf_str_value("length", pcf_process_name_length+20)
        pcf_data = pcf_process_name.rawData()+pcf_process_command.rawData()
        pcf.set_pcf_value("data", pcf_data)
        pcf_packet = {}
        pcf_packet["pcf_packet"] = pcf._mq_pcf
        pcf.set_pcf_value("command", 0x00000005)
        pcf.set_pcf_value("parameter_count", 0x00000002)
        pcf_length = lengths.calculate_segment_length(pcf_packet)
        model_queue_name = self.get_queue_name(model_queue)
        object_queue_manager_name = self.get_queue_manager_name(object_queue_manager)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("reply_to_queue", model_queue_name)
        md.set_md_value("reply_to_qm", object_queue_manager_name)
        put.set_put_value("data_length", pcf_length)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        whole_packet["pcf"] = pcf._mq_pcf
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        create_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+pcf.rawData()
        return create_string

    def get_pcf_start_service(self, object_handle, model_queue, object_queue_manager):
        # Construct the PCF data
        lengths = LengthCalculation()
        pcf = mq_pcf()
        pcf_service_name = pcf_string()
        pcf_service_name.set_pcf_str_value("data", 'hack')
        pcf_service_name.set_pcf_str_value("code", 0x0000081d)
        pcf_service_name.set_pcf_str_value("encoding", 0x000004b8)
        pcf_service_name_length = len(pcf_service_name.get_pcf_str_value("data")[0])
        pcf_service_name.set_pcf_str_value("string_length", pcf_service_name_length)
        pcf_service_name.set_pcf_str_value("length", pcf_service_name_length+20)
        pcf_data = pcf_service_name.rawData()
        pcf.set_pcf_value("data", pcf_data)
        pcf_packet = {}
        pcf_packet["pcf_packet"] = pcf._mq_pcf
        pcf.set_pcf_value("command", 0x0000009b)
        pcf.set_pcf_value("parameter_count", 0x00000001)
        pcf_length = lengths.calculate_segment_length(pcf_packet)
        model_queue_name = self.get_queue_name(model_queue)
        object_queue_manager_name = self.get_queue_manager_name(object_queue_manager)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("reply_to_queue", model_queue_name)
        md.set_md_value("reply_to_qm", object_queue_manager_name)
        put.set_put_value("data_length", pcf_length)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        whole_packet["pcf"] = pcf._mq_pcf
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        start_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+pcf.rawData()
        return start_string

    def get_pcf_delete_service(self, object_handle, model_queue, object_queue_manager):
        # Construct the PCF data
        lengths = LengthCalculation()
        pcf = mq_pcf()
        pcf_service_name = pcf_string()
        pcf_service_name.set_pcf_str_value("data", 'hack')
        pcf_service_name.set_pcf_str_value("code", 0x0000081d)
        pcf_service_name.set_pcf_str_value("encoding", 0x000004b8)
        pcf_service_name_length = len(pcf_service_name.get_pcf_str_value("data")[0])
        pcf_service_name.set_pcf_str_value("string_length", pcf_service_name_length)
        pcf_service_name.set_pcf_str_value("length", pcf_service_name_length+20)
        pcf_data = pcf_service_name.rawData()
        pcf.set_pcf_value("data", pcf_data)
        pcf_packet = {}
        pcf_packet["pcf_packet"] = pcf._mq_pcf
        pcf.set_pcf_value("command", 0x00000098)
        pcf.set_pcf_value("parameter_count", 0x00000001)
        pcf_length = lengths.calculate_segment_length(pcf_packet)
        model_queue_name = self.get_queue_name(model_queue)
        object_queue_manager_name = self.get_queue_manager_name(object_queue_manager)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("reply_to_queue", model_queue_name)
        md.set_md_value("reply_to_qm", object_queue_manager_name)
        put.set_put_value("data_length", pcf_length)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        whole_packet["pcf"] = pcf._mq_pcf
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        delete_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+pcf.rawData()
        return delete_string

    def get_pcf_inquire_cluster(self, object_handle, model_queue, object_queue_manager):
        # Construct the PCF data
        lengths = LengthCalculation() 
        pcf = mq_pcf()
        pcf_cluster_qmgr_name = pcf_string()
        pcf_cluster_qmgr_name.set_pcf_str_value("data", '*   ')
        pcf_cluster_qmgr_name.set_pcf_str_value("code", 0x000007ef)
        pcf_cluster_qmgr_name.set_pcf_str_value("encoding", 0x000004b8)
        pcf_cluster_qmgr_name_length = len(pcf_cluster_qmgr_name.get_pcf_str_value("data")[0])
        pcf_cluster_qmgr_name.set_pcf_str_value("string_length", pcf_cluster_qmgr_name_length)
        pcf_cluster_qmgr_name.set_pcf_str_value("length", pcf_cluster_qmgr_name_length+20)
        pcf_cluster_qmgr_attrs = pcf_int_list()
        pcf_cluster_qmgr_attrs.set_pcf_int_list_value("data", '\x00\x00\x03\xf1')
        pcf_cluster_qmgr_attrs.set_pcf_int_list_value("code", 0x00000445)
        pcf_cluster_qmgr_attrs_length = len(pcf_cluster_qmgr_attrs.get_pcf_int_list_value("data")[0])
        pcf_cluster_qmgr_attrs.set_pcf_int_list_value("length", pcf_cluster_qmgr_attrs_length+16)
        pcf_cluster_name = pcf_string_filter()
        pcf_cluster_name.set_pcf_str_filter_value("data", '*   ')
        pcf_cluster_name.set_pcf_str_filter_value("code", 0x000007ed)
        pcf_cluster_name_length = len(pcf_cluster_name.get_pcf_str_filter_value("data")[0])
        pcf_cluster_name.set_pcf_str_filter_value("string_length", 0x00000001) # pcf_cluster_name_length)
        pcf_cluster_name.set_pcf_str_filter_value("length", pcf_cluster_name_length+24)
        pcf_data = pcf_cluster_qmgr_name.rawData()+ pcf_cluster_qmgr_attrs.rawData()+pcf_cluster_name.rawData()
        pcf.set_pcf_value("data", pcf_data)
        pcf_packet = {}
        pcf_packet["pcf_packet"] = pcf._mq_pcf
        pcf.set_pcf_value("command", 0x00000046)
        pcf.set_pcf_value("parameter_count", 0x00000003)
        pcf.set_pcf_value("version", 0x00000003)
        pcf_length = lengths.calculate_segment_length(pcf_packet)
        model_queue_name = self.get_queue_name(model_queue)
        object_queue_manager_name = self.get_queue_manager_name(object_queue_manager)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("reply_to_queue", model_queue_name)
        md.set_md_value("reply_to_qm", object_queue_manager_name)
        md.set_md_value("version", 0x00000002)
        md.set_md_value("report", 0x00000040)
        put.set_put_value("data_length", pcf_length)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        whole_packet["pcf"] = pcf._mq_pcf
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        inquire_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+pcf.rawData()
        return inquire_string

    def get_pcf_inquire_processes(self, object_handle, model_queue, object_queue_manager):
        # Construct the PCF data
        lengths = LengthCalculation()
        pcf = mq_pcf()
        pcf_process_name = pcf_string()
        pcf_process_name.set_pcf_str_value("data", '*   ')
        pcf_process_name.set_pcf_str_value("code", 0x000007dc)
        pcf_process_name.set_pcf_str_value("encoding", 0x000004b8)
        pcf_process_name_length = len(pcf_process_name.get_pcf_str_value("data")[0])
        pcf_process_name.set_pcf_str_value("string_length", pcf_process_name_length)
        pcf_process_name.set_pcf_str_value("length", pcf_process_name_length+20)
        pcf_data = pcf_process_name.rawData()
        pcf.set_pcf_value("data", pcf_data)
        pcf_packet = {}
        pcf_packet["pcf_packet"] = pcf._mq_pcf
        pcf.set_pcf_value("command", 0x00000013)
        pcf.set_pcf_value("parameter_count", 0x00000001)
        pcf_length = lengths.calculate_segment_length(pcf_packet)
        model_queue_name = self.get_queue_name(model_queue)
        object_queue_manager_name = self.get_queue_manager_name(object_queue_manager)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        pmo = mq_put_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x86)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("reply_to_queue", model_queue_name)
        md.set_md_value("reply_to_qm", object_queue_manager_name)
        md.set_md_value("version", 0x00000002)
        md.set_md_value("report", 0x00000000)
        put.set_put_value("data_length", pcf_length)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_put_message_options"] = pmo._put_message
        whole_packet["mq_put"] = put._mq_put
        whole_packet["pcf"] = pcf._mq_pcf
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", packet_length)
        inquire_string = tsh.rawData()+api.rawData()+md.rawData()+pmo.rawData()+put.rawData()+pcf.rawData()
        return inquire_string

    def get_get(self, object_handle, queue_name):
        queue_name = self.get_queue_name(queue_name)
        tsh = websphere_mq_packet()
        api = mq_api_header()
        md = mq_message_descriptor()
        gmo = mq_get_message_options()
        put = mq_put()
        tsh.set_tsh_value("segment_type", 0x85)
        tsh.set_tsh_value("control_flags", 0x30)
        api.set_api_value("object_handle", object_handle)
        md.set_md_value("message_type", 0x00000008)
        put.set_put_value("data_length", 0x00001000)
        gmo.set_gmo_value("options", 0x00004005)
        whole_packet = {}
        whole_packet["tsh"] = tsh._tsh
        whole_packet["api_header"] = api._api_header
        whole_packet["mq_message_descriptor"] = md._message_descriptor
        whole_packet["mq_get_message_options"] = gmo._get_message
        whole_packet["mq_put"] = put._mq_put
        lengths = LengthCalculation()
        packet_length = lengths.calculate_segment_length(whole_packet)
        tsh.set_tsh_value("segment_length", packet_length)
        api.set_api_value("reply_length", 0x000011ec)
        open_string = tsh.rawData()+api.rawData()+md.rawData()+gmo.rawData()+put.rawData()
        return open_string

class static_data:

    def __init__(self):
        self._completion_codes = {    '\xff\xff\xff\xff' : [ -1, 'Unknown'],
                                      '\x00\x00\x00\x00' : [ 0, "OK"],
                                      '\x00\x00\x00\x01' : [ 1, "Warning"],
                                      '\x00\x00\x00\x02' : [ 2, "Fail"]
                                 }
        self._status_codes = {        '\x00\x00\x00\x00' : [ 0, "OK"],
                                      '\x00\x00\x00\x01' : [ 1, "Remote Channel Not Found"],
                                      '\x00\x00\x00\x02' : [ 2, "Bad Remote Channel Type"],
                                      '\x00\x00\x00\x03' : [ 3, "Remote Queue Manager Not Available !"],
                                      '\x00\x00\x00\x04' : [ 4, "Message Sequence Error"],
                                      '\x00\x00\x00\x05' : [ 5, "Remote QM Terminating"],
                                      '\x00\x00\x00\x06' : [ 6, "Message Not Received"],
                                      '\x00\x00\x00\x07' : [ 7, "Channel Closed"],
                                      '\x00\x00\x00\x08' : [ 8, "Discovery Interval Expired"],
                                      '\x00\x00\x00\x0a' : [ 10, "Remote Protocol Error"],
                                      '\x00\x00\x00\x14' : [ 20, "Bind Failed"],
                                      '\x00\x00\x00\x15' : [ 21, "Message Wrap Different"],
                                      '\x00\x00\x00\x16' : [ 22, "Remote Channel Unavailable"],
                                      '\x00\x00\x00\x17' : [ 23, "Terminated By Remote Exit"],
                                      '\x00\x00\x00\x18' : [ 24, "SSL Remote Bad Cipher!"],
                                      '\x00\x00\x00\x19' : [ 25, "SSL Invalid DN in Certificate"], 
                                      '\x00\x00\x00\x1a' : [ 26, "SSL Invalid Client Certificate!"]
                                 }


        self._reason_codes = {        
                                      '\x00\x00\x07\xe3' : [ 2019, "Object handle not valid"],
                                      '\x00\x00\x07\xeb' : [ 2027, "Missing Reply to Queue"],
                                      '\x00\x00\x07\xed' : [ 2029, "Incorrect Message Version"],
                                      '\x00\x00\x07\xf1' : [ 2033, "No more messages on Queue"],
                                      '\x00\x00\x07\xf3' : [ 2035, "Not Authorised"],
                                      '\x00\x00\x07\xf5' : [ 2037, "Not Open for Browse"],
                                      '\x00\x00\x07\xf7' : [ 2039, "Not Open for Output"],
                                      '\x00\x00\x07\xfa' : [ 2042, "Object in use"],
                                      '\x00\x00\x07\xfd' : [ 2045, "Option not valid for object type"],
                                      '\x00\x00\x08\x03' : [ 2051, "Put Inhibited"],
                                      '\x00\x00\x08\x0a' : [ 2058, "Queue Manager Name Error"],
                                      '\x00\x00\x08\x0f' : [ 2063, "Security Error"],
                                      '\x00\x00\x08\x20' : [ 2080, "Truncated Message Failed"],
                                      '\x00\x00\x08\x22' : [ 2082, "Unknown alias base queue"],
                                      '\x00\x00\x08\x25' : [ 2085, "Unknown Queue Name"],
                                      '\x00\x00\x08\x65' : [ 2149, "PCF Error"],
                                      '\x00\x00\x08\xbd' : [ 2237, "CFIN Error"],
                                      '\x00\x00\x0b\xc0' : [ 3008, "Command Failed"],
                                      '\x00\x00\x0c\x4e' : [ 3150, "Filter Error"],
                                      '\x00\x00\x0c\x68' : [ 3176, "Command Not Available"]
                                 }

        self._packet_types = {        '\x01' : [ 1, "Initial Data"],
                                      '\x02' : [ 2, "Resync Data"],
                                      '\x03' : [ 3, "Reset Data"],
                                      '\x04' : [ 4, "Message Data"],
                                      '\x05' : [ 5, "Status Data"],
                                      '\x06' : [ 6, "Security Data"],
                                      '\x07' : [ 7, "Ping Data"],
                                      '\x08' : [ 8, "UserID Data"],
                                      '\x09' : [ 9, "Heartbeat"],
                                      '\x81' : [ 129, "MQ Connection"],
                                      '\x82' : [ 130, "MQ Discovery"],
                                      '\x83' : [ 131, "MQ Open"],
                                      '\x84' : [ 132, "MQ Close"],
                                      '\x85' : [ 133, "MQ Get"],
                                      '\x86' : [ 134, "MQ Put"],
                                      '\x87' : [ 135, "MQ Put1"],
                                      '\x88' : [ 136, "MQ Set"],
                                      '\x89' : [ 137, "MQ Inquire"],
                                      '\x8a' : [ 138, "MQ Commit"],
                                      '\x8b' : [ 139, "MQ Back"],
                                      '\x8c' : [ 140, "SPI"],
                                      '\x91' : [ 145, "MQ Connection Reply"],
                                      '\x92' : [ 146, "MQ Discovery Reply"],
                                      '\x93' : [ 147, "MQ Open Reply"],
                                      '\x94' : [ 148, "MQ Close Reply"],
                                      '\x95' : [ 149, "MQ Get Reply"],
                                      '\x96' : [ 150, "MQ Put Reply"],
                                      '\x97' : [ 151, "MQ Put1 Reply"],
                                      '\x98' : [ 152, "MQ Set Reply"],
                                      '\x99' : [ 153, "MQ Inquire Reply"],
                                      '\x9a' : [ 154, "MQ Commit Reply"],
                                      '\x9b' : [ 155, "MQ Back Reply"],
                                      '\x9c' : [ 156, "SPI Reply"],
                                      '\xa1' : [ 161, "XA Start"],
                                      '\xa2' : [ 162, "XA End"],
                                      '\xa3' : [ 163, "XA Open"],
                                      '\xa4' : [ 164, "XA Close"],
                                      '\xa5' : [ 165, "XA Prepare"],
                                      '\xa6' : [ 166, "XA Commit"],
                                      '\xa7' : [ 167, "XA Rollback"],
                                      '\xa8' : [ 168, "XA Forget"],
                                      '\xa9' : [ 169, "XA Recover"],
                                      '\xaa' : [ 170, "XA Complete"],
                                      '\xb1' : [ 177, "XA Start Reply"],
                                      '\xb2' : [ 178, "XA End Reply"],
                                      '\xb3' : [ 179, "XA Open Reply"],
                                      '\xb4' : [ 180, "XA Close Reply"],
                                      '\xb5' : [ 181, "XA Prepare Reply"],
                                      '\xb6' : [ 182, "XA Commit Reply"],
                                      '\xb7' : [ 183, "XA Rollback Reply"],
                                      '\xb8' : [ 184, "XA Forget Reply"],
                                      '\xb9' : [ 185, "XA Recover Reply"],
                                      '\xba' : [ 186, "XA Complete Reply"]
                                 }

        self._pcf_list_codes = {      '\x00\x00\x04\xca' : "Header Compression",
                                      '\x00\x00\x06\x27' : "Header Compression",
                                      '\x00\x00\x06\x28' : "Message Compression",
                                      '\x00\x00\x0b\xc4' : "Process Names"
                                 }

        self._pcf_int_codes = {       '\x00\x00\x00\x01' : ["Application Type", 0 , "NULL"], 
                                      '\x00\x00\x00\x02' : ["Accounting Connection Interval", 0 , "NULL"],
                                      '\x00\x00\x00\x03' : ["Current Queue Depth", 0, "NULL"],
                                      '\x00\x00\x00\x04' : ["Definition Input Open Option", 1, { '\x00\x00\x00\x01' : "Input as Queue Defintion", '\x00\x00\x00\x02' : "Input Shared", '\x00\x00\x00\x04' : "Input Exclusive", '\x00\x00\x00\x08' : "Browse", '\x00\x00\x00\x10' : "Output", '\x00\x00\x00\x20' : "Inquire", '\x00\x00\x00\x40' : "Set", '\x00\x00\x40\x00' : "Bind On Open", '\x00\x00\x80\x00' : "Bind Not Fixed", '\x00\x00\x00\x00' : "Bind as Queue Definition", '\x00\x00\x00\x80' : "Save All Context", '\x00\x00\x01\x00' : "Pass Identity Context", '\x00\x00\x02\x00' : "Pass All Context", '\x00\x00\x04\x00' : "Set Identity Context", '\x00\x00\x08\x00' : "Set All Context", '\x00\x00\x10\x00' : "Alternate User Authority", '\x00\x00\x20\x00' : "Fail if Quiescing", '\x00\x01\x00\x00' : "Resolve Names", '\x00\x04\x00\x00' : "Resolve Local Queue"}],
                                      '\x00\x00\x00\x05' : ["Definition Persistence", 0, "NULL"],
                                      '\x00\x00\x00\x06' : ["Definition Priority", 0, "NULL"],
                                      '\x00\x00\x00\x07' : ["Definition Type", 1, { '\x00\x00\x00\x01' : "Predefined", '\x00\x00\x00\x02' : "Permanent Dynamic", '\x00\x00\x00\x03' : "Temporary Dynamic", '\x00\x00\x00\x04' : "Shared Dynamic"}],
                                      '\x00\x00\x00\x08' : ["Harden Get Backout", 1, {'\x00\x00\x00\x00' : "Not Hardened", '\x00\x00\x00\x01' : "Hardened" }],
                                      '\x00\x00\x00\x09' : ["Inhibit Get", 1, {'\x00\x00\x00\x00' : "Allowed", '\x00\x00\x00\x01' : "Inhibited" }],
                                      '\x00\x00\x00\x0a' : ["Inhibit Put", 1, {'\x00\x00\x00\x00' : "Allowed", '\x00\x00\x00\x01' : "Inhibited" }],
                                      '\x00\x00\x00\x0b' : ["Maximum Handles", 0, "NULL"],
                                      '\x00\x00\x00\x0c' : ["Usage", 1, {'\x00\x00\x00\x00' : "Normal", '\x00\x00\x00\x01' : "Transmission" }],
                                      '\x00\x00\x00\x0d' : ["Maximum Message Length", 0, "NULL"],
                                      '\x00\x00\x00\x0e' : ["Maximum Priority", 0, "NULL"],
                                      '\x00\x00\x00\x0f' : ["Maximum Queue Depth", 0, "NULL"],
                                      '\x00\x00\x00\x10' : ["Message Delivery Sequence", 1, {'\x00\x00\x00\x00' : "Priority", '\x00\x00\x00\x01' : "FIFO" }],
                                      '\x00\x00\x00\x11' : ["Open Input Count", 0, "NULL"],
                                      '\x00\x00\x00\x12' : ["Open Output Count", 0, "NULL"],
                                      '\x00\x00\x00\x13' : ["Name Count", 0, "NULL"],
                                      '\x00\x00\x00\x14' : ["Queue Type", 1, { '\x00\x00\x00\x01' : "Local", '\x00\x00\x00\x02' : "Model", '\x00\x00\x00\x03' : "Alias", '\x00\x00\x00\x06' : "Remote", '\x00\x00\x00\x07' : "Cluster" }],
                                      '\x00\x00\x00\x15' : ["Retention Interval", 0, "NULL"],
                                      '\x00\x00\x00\x16' : ["Backout Threshold", 0, "NULL"],
                                      '\x00\x00\x00\x17' : ["Shareability", 1, {'\x00\x00\x00\x00' : "Not Shareable", '\x00\x00\x00\x01' : "Shareable" }],
                                      '\x00\x00\x00\x18' : ["Trigger Control", 1, {'\x00\x00\x00\x00' : "Off", '\x00\x00\x00\x01' : "On" }],
                                      '\x00\x00\x00\x19' : ["Trigger Interval", 0, "NULL"],
                                      '\x00\x00\x00\x1a' : ["Trigger Message Priority", 0, "NULL"],
                                      '\x00\x00\x00\x1b' : ["CPI Level", 0, "NULL"],
                                      '\x00\x00\x00\x1c' : ["Trigger Type", 1, {  '\x00\x00\x00\x00' : "None", '\x00\x00\x00\x01' : "First", '\x00\x00\x00\x02' : "Every", '\x00\x00\x00\x02' : "Depth" }],
                                      '\x00\x00\x00\x1d' : ["Trigger Depth", 0, "NULL"],
                                      '\x00\x00\x00\x1e' : ["Sync Point", 0, "NULL"],
                                      '\x00\x00\x00\x1f' : ["Command Level", 1, { '\x00\x00\x00\xdc' : "Websphere MQ v2.2", '\x00\x00\x00\xdd' : "Websphere MQ v2.2.1", '\x00\x00\x01\x40' : "Websphere MQ v3.2", '\x00\x00\x01\xa4' : "Websphere MQ v4.2", '\x00\x00\x01\xf4' : "Websphere MQ v5.0", '\x00\x00\x01\xfe' : "Websphere MQ v5.1", '\x00\x00\x02\x08' : "Websphere MQ v5.2", '\x00\x00\x02\x12' : "Websphere MQ v5.3", '\x00\x00\x02\x58' : "Websphere MQ v6.0" }],
                                      '\x00\x00\x00\x20' : ["Operating System Type", 1, { '\x00\x00\x00\x02' : "OS2", '\x00\x00\x00\x03' : "HP-UX, AIX, Linux or Solaris", '\x00\x00\x00\x04' : "OS400", '\x00\x00\x00\x0B' : "Windows" }],
                                      '\x00\x00\x00\x21' : ["Maximum Uncommitted Messages", 0, "NULL"],
                                      '\x00\x00\x00\x22' : ["Distribution List", 1, {'\x00\x00\x00\x00' : "Not Supported", '\x00\x00\x00\x01' : "Supported" }],
                                      '\x00\x00\x00\x23' : ["Time Since Reset", 0, "NULL"],
                                      '\x00\x00\x00\x24' : ["High Queue Depth", 0, "NULL"],
                                      '\x00\x00\x00\x25' : ["Message Enq Count", 0, "NULL"],
                                      '\x00\x00\x00\x26' : ["Message Deq Count", 0, "NULL"],
                                      '\x00\x00\x00\x27' : ["Expiry Interval", 0, "NULL"],
                                      '\x00\x00\x00\x28' : ["Queue Depth High Limit", 0, "NULL"],
                                      '\x00\x00\x00\x29' : ["Queue Depth Low Limit", 0, "NULL"],
                                      '\x00\x00\x00\x2a' : ["Queue Depth Max Event", 0, "NULL"],
                                      '\x00\x00\x00\x2b' : ["Queue Depth High Event", 0, "NULL"],
                                      '\x00\x00\x00\x2c' : ["Queue Depth Low Event", 0, "NULL"],
                                      '\x00\x00\x00\x2d' : ["Scope", 1, {'\x00\x00\x00\x01' : "Queue Manager", '\x00\x00\x00\x02' : "Cell" }],
                                      '\x00\x00\x00\x2e' : ["Service Interval Event", 0, "NULL"],
                                      '\x00\x00\x00\x2f' : ["Authority Event", 0, "NULL"],
                                      '\x00\x00\x00\x30' : ["Inhibit Event", 0, "NULL"],
                                      '\x00\x00\x00\x31' : ["Local Event", 0, "NULL"],
                                      '\x00\x00\x00\x32' : ["Remote Event", 0, "NULL"],
                                      '\x00\x00\x00\x33' : ["Configuration Event", 0, "NULL"],
                                      '\x00\x00\x00\x34' : ["Start Stop Event", 0, "NULL"],
                                      '\x00\x00\x00\x35' : ["Performance Event", 0, "NULL"],
                                      '\x00\x00\x00\x36' : ["Queue Service Interval", 0, "NULL"],
                                      '\x00\x00\x00\x37' : ["Channel Auto Definition", 0, "NULL"],
                                      '\x00\x00\x00\x38' : ["Channel Auto Definition Event", 0, "NULL"],
                                      '\x00\x00\x00\x39' : ["Index Type", 0, "NULL"],
                                      '\x00\x00\x00\x3a' : ["Cluster Workload Length", 0, "NULL"],
                                      '\x00\x00\x00\x3b' : ["Cluster Queue Type", 0, "NULL"],
                                      '\x00\x00\x00\x3c' : ["Archive", 0, "NULL"],
                                      '\x00\x00\x00\x3d' : ["Definition Bind", 0, "NULL"],
                                      '\x00\x00\x00\x3e' : ["Pageset ID", 0, "NULL"],
                                      '\x00\x00\x00\x3f' : ["QSG Disp", 0, "NULL"],
                                      '\x00\x00\x00\x40' : ["Intra Group Queuing", 0, "NULL"],
                                      '\x00\x00\x00\x41' : ["Put Authority", 0, "NULL"],
                                      '\x00\x00\x00\x42' : ["Authority Info Type", 1, {'\x00\x00\x00\x01' : "CRL LDAP"}],
                                      '\x00\x00\x00\x43' : ["Unknown", 0, "NULL"],
                                      '\x00\x00\x00\x44' : ["Auth Info Type", 0, "NULL"],
                                      '\x00\x00\x00\x45' : ["SSL Tasks", 0, "NULL"],
                                      '\x00\x00\x00\x46' : ["CF Level", 0, "NULL"],
                                      '\x00\x00\x00\x47' : ["CF Recover", 0, "NULL"],
                                      '\x00\x00\x00\x48' : ["Namelist Type", 0, "NULL"],
                                      '\x00\x00\x00\x49' : ["Channel Event", 0, "NULL"],
                                      '\x00\x00\x00\x4c' : ["SSL Reset Count", 0, "NULL"],
                                      '\x00\x00\x00\x4e' : ["NPM Class", 0, "NULL"],
                                      '\x00\x00\x00\x5d' : ["IP Address Version", 0, "NULL"],
                                      '\x00\x00\x00\x5e' : ["Logger Event", 0, "NULL"],
                                      '\x00\x00\x00\x5f' : ["Cluster Workload Queue Rank", 0, "NULL"],
                                      '\x00\x00\x00\x60' : ["Cluster Workload Queue Priority", 0, "NULL"],
                                      '\x00\x00\x00\x61' : ["Cluster Workload MRU Channels", 0, "NULL"],
                                      '\x00\x00\x00\x62' : ["Cluster Workload Use Queue", 0, "NULL"],
                                      '\x00\x00\x00\x77' : ["Channel Init Control", 0, "NULL"],
                                      '\x00\x00\x00\x78' : ["Command Server Control", 0, "NULL"],
                                      '\x00\x00\x00\x79' : ["Service Type", 0, "NULL"],
                                      '\x00\x00\x00\x7a' : ["Monitoring Channel", 0, "NULL"],
                                      '\x00\x00\x00\x7b' : ["Monitoring Queue", 0, "NULL"],
                                      '\x00\x00\x00\x7c' : ["Monitoring Auto Cluster Sender", 0, "NULL"],
                                      '\x00\x00\x00\x7f' : ["Statistics MQI", 0, "NULL"],
                                      '\x00\x00\x00\x80' : ["Statistics Queue", 0, "NULL"],
                                      '\x00\x00\x00\x81' : ["Statistics Channel", 0, "NULL"],
                                      '\x00\x00\x00\x82' : ["Statistics Auto Cluster Sender", 0, "NULL"],
                                      '\x00\x00\x00\x83' : ["Statistics Interval", 0, "NULL"],
                                      '\x00\x00\x00\x85' : ["Accounting Connection MQI", 0, "NULL"],
                                      '\x00\x00\x00\x86' : ["Accounting Connection Queue", 0, "NULL"],
                                      '\x00\x00\x00\x87' : ["Coded Char Set ID", 0, "NULL"],
                                      '\x00\x00\x00\x88' : ["Accounting Connection Override", 1, { '\x00\x00\x00\x00' : "No", '\x00\x00\x00\x01' : "Yes" }],
                                      '\x00\x00\x00\x89' : ["Trace Route Recording", 0, "NULL"],
                                      '\x00\x00\x00\x8a' : ["Activity Recording", 0, "NULL"],
                                      '\x00\x00\x03\xf4' : ["Parameter ID", 0, "NULL"],
                                      '\x00\x00\x03\xf5' : ["Error Identifier", 0, "NULL"],
                                      '\x00\x00\x03\xfc' : ["Reason Qualifier", 0, { '\x00\x00\x00\x01' : "Connection Not Authorised", '\x00\x00\x00\x02' : "Open Not Authorised", '\x00\x00\x00\x03' : "Close Not Authorised", '\x00\x00\x00\x04' : "Command Not Authorised", '\x00\x00\x00\x05' : "Queue Manager Stopping", '\x00\x00\x00\x06' : "Queue Manager Quiescing", '\x00\x00\x00\x07' : "Channel Stopped OK", '\x00\x00\x00\x08' : "Channel Stopped Error", '\x00\x00\x00\x09' : "Channel Stopped Retry", '\x00\x00\x00\x0a' : "Bridge Stopped OK", '\x00\x00\x00\x0b' : "Bridge Stopped Error", '\x00\x00\x00\x0c' : "SSL Handshake Error", '\x00\x00\x00\x0d' : "SSL Cipher Spec Error", '\x00\x00\x00\x0e' : "SSL Client Auth Error", '\x00\x00\x00\x0f' : "SSL Peer Name Error" } ],
                                      '\x00\x00\x03\xfe' : ["Open Options", 0, "NULL"],
                                      '\x00\x00\x03\xff' : ["Open Type", 0, "NULL"],
                                      '\x00\x00\x04\x00' : ["Process ID", 0, "NULL"],
                                      '\x00\x00\x04\x01' : ["Thread ID", 0, "NULL"],
                                      '\x00\x00\x04\x02' : ["Queue Status Attributes", 0, "NULL"],
                                      '\x00\x00\x04\x03' : ["Uncommitted Messages", 0, "NULL"],
                                      '\x00\x00\x04\x04' : ["Unknown", 0, "NULL"],
                                      '\x00\x00\x04\x3c' : ["Queue Manager Definition Type", 0, "NULL"],
                                      '\x00\x00\x04\x3d' : ["Queue Manager Type", 0, "NULL"],
                                      '\x00\x00\x04\x3f' : ["Suspend", 0, "NULL"],
                                      '\x00\x00\x04\x4a' : ["Open Input Type", 0, "NULL"],
                                      '\x00\x00\x04\x4b' : ["Open Output", 0, "NULL"],
                                      '\x00\x00\x04\x4c' : ["Open Set", 0, "NULL"],
                                      '\x00\x00\x04\x4d' : ["Open Inquire", 0, "NULL"],
                                      '\x00\x00\x04\x4e' : ["Open Browse", 0, "NULL"],
                                      '\x00\x00\x04\x4f' : ["Queue Status Type", 0, "NULL"],
                                      '\x00\x00\x04\x50' : ["Queue Handle", 0, "NULL"],
                                      '\x00\x00\x04\x51' : ["Queue Status", 0, "NULL"],
                                      '\x00\x00\x04\x6c' : ["Unknown", 0, "NULL"],
                                      '\x00\x00\x04\xcb' : ["Unknown", 0, "NULL"],
                                      '\x00\x00\x05\xdd' : ["Xmit Protocol Type", 0, "NULL"],
                                      '\x00\x00\x05\xde' : ["Batch Size", 0, "NULL"],
                                      '\x00\x00\x05\xdf' : ["Discovery Interval", 0, "NULL"],
                                      '\x00\x00\x05\xe0' : ["Short Timer", 0, "NULL"],
                                      '\x00\x00\x05\xe1' : ["Short Retry", 0, "NULL"],
                                      '\x00\x00\x05\xe2' : ["Long Timer", 0, "NULL"],
                                      '\x00\x00\x05\xe3' : ["Long Retry", 0, "NULL"],  
                                      '\x00\x00\x05\xe4' : ["Put Authority", 1, {'\x00\x00\x00\x01' : "Default", '\x00\x00\x00\x02' : "Context", '\x00\x00\x00\x03' : "Only MCA", '\x00\x00\x00\x04' : "Alternate or MCA" }],
                                      '\x00\x00\x05\xe5' : ["Sequence Number Wrap", 0 , "NULL"],
                                      '\x00\x00\x05\xe6' : ["Max Message Length", 0, "NULL"],
                                      '\x00\x00\x05\xe7' : ["Channel Type", 1, {'\x00\x00\x00\x01' : "Sender", '\x00\x00\x00\x02' : "Server", '\x00\x00\x00\x03' : "Receiver", '\x00\x00\x00\x04' : "Requester", '\x00\x00\x00\x05' : "All", '\x00\x00\x00\x06' : "Client Connection", '\x00\x00\x00\x07' : "Server Connection", '\x00\x00\x00\x08' : "Cluster Receiver", '\x00\x00\x00\x09' : "Cluster Sender"}],
                                      '\x00\x00\x05\xeb' : ["Data Conversion", 0 , "NULL"],
                                      '\x00\x00\x05\xed' : ["MCA Type", 0 , "NULL"],
                                      '\x00\x00\x05\xf7' : ["Channel Status", 0 , "NULL"],
                                      '\x00\x00\x06\x08' : ["MR Count", 0, "NULL"],
                                      '\x00\x00\x06\x09' : ["MR Interval", 0, "NULL"],
                                      '\x00\x00\x06\x1a' : ["NPM Speed", 0 , "NULL"],
                                      '\x00\x00\x06\x1b' : ["Heartbeat Interval", 0, "NULL"],
                                      '\x00\x00\x06\x1c' : ["Batch Interval", 0 , "NULL"],
                                      '\x00\x00\x06\x1d' : ["Network Priority", 0 , "NULL"],
                                      '\x00\x00\x06\x1e' : ["Keep-alive Interval", 0 , "NULL"],
                                      '\x00\x00\x06\x1f' : ["Batch Heartbeat", 0 , "NULL"],
                                      '\x00\x00\x06\x20' : ["SSL Client Auth", 0, "NULL"],
                                      '\x00\x00\x06\x27' : ["Header Compression", 0, "NULL"],
                                      '\x00\x00\x06\x28' : ["Message Compression", 0, "NULL"],
                                      '\x00\x00\x06\x29' : ["CLWL Channel Rank", 0, "NULL"],
                                      '\x00\x00\x06\x2a' : ["CLWL Channel Priority", 0, "NULL"],
                                      '\x00\x00\x06\x2b' : ["CLWL Channel Weight", 0, "NULL"]
                                 }

        self._pcf_string_codes = {    '\x00\x00\x07\xd2' : "Base Queue Name",
                                      '\x00\x00\x07\xd3' : "Command Input Queue Name",
                                      '\x00\x00\x07\xd4' : "Creation Date",
                                      '\x00\x00\x07\xd5' : "Creation Time",
                                      '\x00\x00\x07\xd6' : "Dead Letter Queue Name",
                                      '\x00\x00\x07\xd8' : "Initiation Queue Name",
                                      '\x00\x00\x07\xdc' : "Process Name",
                                      '\x00\x00\x07\xdd' : "Queue Description",
                                      '\x00\x00\x07\xde' : "Queue Manager Description",
                                      '\x00\x00\x07\xdf' : "Queue Manager Name",
                                      '\x00\x00\x07\xe0' : "Queue Name",
                                      '\x00\x00\x07\xe3' : "Remote Queue Manager Name",
                                      '\x00\x00\x07\xe2' : "Remote Queue Name",
                                      '\x00\x00\x07\xe3' : "Backout req Queue Name",
                                      '\x00\x00\x07\xe7' : "Trigger Data",
                                      '\x00\x00\x07\xe8' : "Xmit Queue Name",
                                      '\x00\x00\x07\xe9' : "Defined Transmit Queue Name",
                                      '\x00\x00\x07\xea' : "Channel Auto Defined Exit",
                                      '\x00\x00\x07\xeb' : "Alteration Date",
                                      '\x00\x00\x07\xec' : "Alteration Time",
                                      '\x00\x00\x07\xed' : "Cluster Name",
                                      '\x00\x00\x07\xee' : "Cluster Namelist",
                                      '\x00\x00\x07\xef' : "Cluster Queue Manager Name",
                                      '\x00\x00\x07\xf0' : "Queue Manager Identifier",
                                      '\x00\x00\x07\xf1' : "Cluster Workload Exit",
                                      '\x00\x00\x07\xf2' : "Cluster Workload Data",
                                      '\x00\x00\x07\xf3' : "Repository Name",
                                      '\x00\x00\x07\xf4' : "Repository Namelist",
                                      '\x00\x00\x07\xf5' : "Cluster Date",
                                      '\x00\x00\x07\xf6' : "Cluster Time",
                                      '\x00\x00\x07\xfd' : "Auth Info Name",
                                      '\x00\x00\x07\xfe' : "Auth Info Description",
                                      '\x00\x00\x07\xff' : "LDAP Username",
                                      '\x00\x00\x08\x00' : "LDAP Password",
                                      '\x00\x00\x08\x01' : "SSL Key Repository",
                                      '\x00\x00\x08\x02' : "SSL CRL Namelist",
                                      '\x00\x00\x08\x03' : "SSL Crypto Hardware",
                                      '\x00\x00\x08\x04' : "Command Format Structure Description",
                                      '\x00\x00\x08\x05' : "Auth Info Connection Name",
                                      '\x00\x00\x08\x1d' : "Service Name",
                                      '\x00\x00\x08\x1e' : "Service Description",
                                      '\x00\x00\x08\x1f' : "Service Start Command",
                                      '\x00\x00\x08\x20' : "Service Start Arguments",
                                      '\x00\x00\x08\x21' : "Service Stop Command",
                                      '\x00\x00\x08\x22' : "Service Stop Arguments",
                                      '\x00\x00\x08\x23' : "Stdout Destination",
                                      '\x00\x00\x08\x24' : "Stderr Destination",
                                      '\x00\x00\x0b\xc4' : "Process Names",
                                      '\x00\x00\x0b\xd1' : "User Identifier",
                                      '\x00\x00\x0b\xf2' : "Application Type",
                                      '\x00\x00\x0c\x01' : "Unknown",
                                      '\x00\x00\x0c\x38' : "Unknown",
                                      '\x00\x00\x0c\x39' : "Unknown",
                                      '\x00\x00\x0c\x3a' : "Unknown",
                                      '\x00\x00\x0c\x3b' : "Unknown",
                                      '\x00\x00\x0c\x3c' : "Unknown",
                                      '\x00\x00\x0d\xad' : "Channel Name",
                                      '\x00\x00\x0d\xae' : "Channel Description",
                                      '\x00\x00\x0d\xaf' : "Mode Name",
                                      '\x00\x00\x0d\xb0' : "Xmit Queue Name",
                                      '\x00\x00\x0d\xb1' : "Xmit Queue Name",
                                      '\x00\x00\x0d\xb2' : "Connection Name",
                                      '\x00\x00\x0d\xb3' : "MCA Name",
                                      '\x00\x00\x0d\xb4' : "Security Exit",
                                      '\x00\x00\x0d\xb5' : "Message Exit Name",
                                      '\x00\x00\x0d\xb6' : "Send Exit Name",
                                      '\x00\x00\x0d\xb7' : "Receive Exit Name",
                                      '\x00\x00\x0d\xb9' : "Security Exit User Data",
                                      '\x00\x00\x0d\xba' : "Message Exit User Data",
                                      '\x00\x00\x0d\xbb' : "Send Exit User Data",
                                      '\x00\x00\x0d\xbc' : "Receive Exit User Data",
                                      '\x00\x00\x0d\xbd' : "UserID",
                                      '\x00\x00\x0d\xbe' : "Password",
                                      '\x00\x00\x0d\xc0' : "Local Address",
                                      '\x00\x00\x0d\xc7' : "MCA User ID",
                                      '\x00\x00\x0d\xce' : "MR Exit Name",
                                      '\x00\x00\x0d\xcf' : "MR Exit User Data",
                                      '\x00\x00\x0d\xd8' : "SSL Cipher Spec",
                                      '\x00\x00\x0d\xd9' : "SSL Peer Name"
                                 }

    def print_pcf_int(self, field_type, field_data):
        if self._pcf_int_codes.has_key(field_type):
            if self._pcf_int_codes[field_type][1] == 1:
                #dictionary = self._pcf_int_codes[field_type][2]
                print self._pcf_int_codes[field_type][0]+': '+self._pcf_int_codes[field_type][2][field_data]
            else:
                print self._pcf_int_codes[field_type][0]+': '+str(string.atoi(str(binascii.hexlify(field_data)),16))

    def print_pcf_str(self, field_type, field_data):
        if self._pcf_string_codes.has_key(field_type):
            print self._pcf_string_codes[field_type]+': '+field_data

    def print_pcf_list(self, field_type, field_data):
        if self._pcf_list_codes.has_key(field_type):
            print self._pcf_list_codes[field_type]+': '+binascii.hexlify(field_data)

    def print_pcf_list6(self, field_type, field_data, list_item_number, list_item_length):
        if self._pcf_list_codes.has_key(field_type):
            loop = 0
            data_string = ''
            while loop < list_item_number:
                data = field_data[loop*list_item_length:loop*list_item_length+list_item_length]
                data = data.replace("\x20\x20", "") 
                data_string += data+"\x20"
                loop = loop+1
            print self._pcf_list_codes[field_type]+': '+data_string

    def print_reason(self, reason_string,verbose):
        if self._reason_codes.has_key(reason_string):
            if verbose == 1:
                print "Reason Code "+str(self._reason_codes[reason_string][0])+' - '+self._reason_codes[reason_string][1]

    def print_completion(self, completion_string,verbose):
        if self._completion_codes.has_key(completion_string):
            if verbose == 1:
                print "Completion Code "+str(self._completion_codes[completion_string][0])+' - '+self._completion_codes[completion_string][1]
            if completion_string == '\x00\x00\x00\x00':
                error = 0
            else:
                error = 1
        else:
            error = 1
            print "Invalid Completion Code !!"
        return error 

    def print_status(self, status_string, verbose):
        if self._status_codes.has_key(status_string):
            if verbose == 1:
                print self._status_codes[status_string][1]
            if status_string == '\x00\x00\x00\x00':
                error = 1
            else:
                error = 0 
        else:
            print "Invalid Response Code !!"
            error = 0
        return error

