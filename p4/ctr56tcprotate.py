import ptf
from ptf.base_tests import BaseTest
import ptf.testutils as testutils
import grpc
import bfrt_grpc.bfruntime_pb2_grpc as bfruntime_pb2_grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
# import google.rpc.status_pb2 as status_pb2
# import google.rpc.code_pb2 as code_pb2

import Queue
import os
import logging
import threading
import json
import sys
import random
import math
import time
from collections import namedtuple

from csiphash import siphash24
import netifaces
from ipaddress import ip_address

sleep_tm = float(sys.argv[1])

def rand_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )


def rand_port():
    return random.randint(0, 65535)


def rand_int():
    return random.randint(0, 1024)


def flush_table(table, target):
    ks = []
    x = table.entry_get(target)
    for i in x:
        ks.append(i[1])
    # if None in ks:
    #    ks.remove(None)
    table.entry_del(target, ks)


grpc_addr = 'localhost:50052'
client_id = 1
is_master = False
# p4_name = "pinotv6_64"
# p4_name = "pinotv6_56_src_slice"
p4_name = "pinotv6_56_tcp_firewall"
p4_name = "pinot_quic"
# p4_name = "pinot_quic_skipl"

interface = gc.ClientInterface(
    grpc_addr,
    client_id=client_id,
    device_id=0,
    is_master=is_master)

interface.bind_pipeline_config(p4_name)

target = gc.Target(device_id=0, pipe_id=0xffff)

bfrt_info = interface.bfrt_info_get(p4_name)


forward_table = bfrt_info.table_get("SwitchIngress.forward")
# except_table = bfrt_info.table_get("SwitchIngress.forward_exc1")
# except_table.info.key_field_annotation_add("hdr.ipv4.src_addr", "ipv4")

key1_table = bfrt_info.table_get("SwitchIngress.xor_with_key_1")
key1_table.info.key_field_annotation_add("ig_md.slice1", "ipv4")

key2_table = bfrt_info.table_get("SwitchIngress.xor_with_key_2")
key2_table.info.key_field_annotation_add("ig_md.slice2", "ipv4")

# otp_table1 = bfrt_info.table_get("SwitchIngress.port_enc")
# otp_table2 = bfrt_info.table_get("SwitchIngress.port_dec")

# 138 fruity-03
# 139 spicy-02
# 128 interet
# client_port = 138
client_port = 138
server_port2 = 139
server_port = 128
"""
iface_1 = "veth0"
imac_1 = netifaces.ifaddresses(iface_1)[netifaces.AF_LINK][0]['addr']

iface_2 = "veth2"
imac_2 = netifaces.ifaddresses(iface_2)[netifaces.AF_LINK][0]['addr']

client_mac = str(imac_1)
server_mac = str(imac_2)

print client_mac, server_mac
"""


try:
    flush_table(key1_table, target)
    flush_table(key2_table, target)

except Exception as e:
    print "flush key1", str(e)
    pass

try:
    flush_table(forward_table, target)
except Exception as e:
    print "flush forward", str(e)
    pass

try:
    flush_table(except_table, target)
except Exception as e:
    print "flush except", str(e)
    pass


try:
    flush_table(otp_table1, target)
    flush_table(otp_table2, target)
except Exception as e:
    print "flush otp", str(e)
    pass


def forward_update(ver=0b00, is_mod=False):
    key_list = [forward_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', client_port)]),
                forward_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', server_port)]),
               forward_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', server_port2)])]
    data_list = [forward_table.make_data([gc.DataTuple('port', server_port), gc.DataTuple('ver', ver)], "SwitchIngress.hit"),
                 forward_table.make_data([gc.DataTuple('port', client_port), gc.DataTuple('ver', ver)], "SwitchIngress.hit"),
                forward_table.make_data([gc.DataTuple('port', client_port), gc.DataTuple('ver', ver)], "SwitchIngress.hit"),]

    if is_mod:
        forward_table.entry_mod(target, key_list, data_list)
    else:
        forward_table.entry_add(target, key_list, data_list)


def except_update():
    key_list = [except_table.make_key([gc.KeyTuple('hdr.ipv4.src_addr', "128.112.138.152")])]
    data_list = [except_table.make_data([gc.DataTuple('port', 128)], "SwitchIngress.switchPort")]
    except_table.entry_add(target, key_list, data_list)


def enc_init(ver=0b00, is_mod=False):

# key = b'\x00' * 16  # fix the key for debugging
    key = os.urandom(16)
# keys = [b'\x00' * 16, b'\x01' * 16, b'\x02' * 16,  b'\x03' * 16,  b'\x04' * 16]
# kidx = random.choice([0, 1, 2, 3, 4])
# key = keys[ver] 
    key_list1 = []
    key_list2 = []
    data_list1 = []
    data_list2 = []
    try:
        for slice_idx in [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7]:
            # using os.urandom(16) or other methods
            k1 = bytearray(siphash24(key, str(0)))
            k2 = bytearray(siphash24(key, str(1)))
            k3 = bytearray(siphash24(key, str(2)))

            key_list1 += [key1_table.make_key([
                gc.KeyTuple('ig_md.cur_ver', ver),
                gc.KeyTuple('ig_md.slice1', slice_idx),
            ])]

            data_list1 += [
                key1_table.make_data([
                    gc.DataTuple('k1', k1[4:8]),
                    gc.DataTuple('k2', k1[0:4]),
                    gc.DataTuple('otp1', k2),
                    gc.DataTuple('otp2', k3),
                ],
                "SwitchIngress.get_key_1")
            ]

            key_list2 += [key2_table.make_key([
                gc.KeyTuple('ig_md.cur_ver', ver),
                gc.KeyTuple('ig_md.slice2', slice_idx),

            ])]
            data_list2 += [
                key2_table.make_data([
                    gc.DataTuple('k1', k3[4:8]),
                    gc.DataTuple('k2', k3[0:4]),
                    gc.DataTuple('otp1', k2),
                    gc.DataTuple('otp2', k1),
                ],
                "SwitchIngress.get_key_2")
            ]

        if is_mod:
            key1_table.entry_mod(target, key_list1, data_list1)
            key2_table.entry_mod(target, key_list2, data_list2)
        else:
            key1_table.entry_add(target, key_list1, data_list1)
            key2_table.entry_add(target, key_list2, data_list2)

    except Exception as e:
        print str(e)
        try:
            flush_table(key1_table, target)
            flush_table(key2_table, target)
        except Exception as e:
            pass


forward_update(0b01)
# except_update()
enc_init(0b00)
enc_init(0b01)
enc_init(0b10)

"""
uncomment the following two lines to disable key rotation
for debugging
"""
# interface._tear_down_stream()
# exit()

vers = [0b01, 0b10, 0b00]
init_flag = True
while True:
    for idx in xrange(3):
        cur_tm = time.time()
        ver = vers[idx]
        print cur_tm, "cur_ver is", ver
        forward_update(ver, True)
        if init_flag:
            if idx == 1:
                up_ver = vers[(idx + 1) % 3]
                # print "update ver is", up_ver
                enc_init(up_ver, True)
                init_flag = False
        else:
            up_ver = vers[(idx + 1) % 3]
            # print "update ver is", up_ver
            enc_init(up_ver, True)
        time.sleep(sleep_tm)

interface._tear_down_stream()

