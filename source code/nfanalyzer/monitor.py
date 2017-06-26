#!/usr/bin/env python
#-*- coding: utf-8 -*-

import os
import sys
# The module we need
directory = os.path.dirname(os.path.abspath(__file__))
sys.path.append(directory+"/..")
import rule
import iplist
import date
import nflow
import config
import output

minute_interval = 1

# Get unused IP list
ip_list = iplist.IPList()
unused_list = ip_list.unusedIP
black_list = ip_list.blacklist

def monitorUnusedIP(start_datetime, end_datetime):
    monIP_list = []
    nf = nflow.NetFlow()
    plain = nf.readLog(start_datetime, end_datetime, minute_interval,
                       options=["dst ip in [%s]" % ",".join(unused_list)], 
                       mode="csv")
    for e in nf.parseLogLine(plain, mode="csv"):
        monIP_list.append({'source': e['sa'],
                           'srcport': e['sp'],
                           'target': e['da'],
                           'dstport': e['dp'],
                           'date': e['te']})
    # Output to DB
    output_handler = output.Output(start_datetime, end_datetime)
    output_handler.writeMonIPLog(monIP_list)

def monitorBlacklistIP(start_datetime, end_datetime):
    # Set up the filter rules (blacklist IP)
    # Well Known Ports (0 – 1023)
    # Registered Ports (1024 – 49151)
    # Dynamic or Private Ports (49152 – 65535)
    # We think port 0-10000 as system reversed ports
    blackConn_list = []
    nf = nflow.NetFlow()
    plain = nf.readLog(start_datetime, end_datetime, minute_interval,
                       options=["dst ip in [%s] and src port > 10000" \
                                % ",".join(black_list)], 
                       mode="csv")

    for e in nf.parseLogLine(plain, mode="csv"):
        blackConn_list.append({'src_ip': e['sa'],
                               'dst_ip': e['da'],
                               'src_port': e['sp'],
                               'dst_port': e['dp'],
                               'date': e['te']})

    # Output to DB
    output_handler = output.Output(start_datetime, end_datetime)
    output_handler.writeBlackList(blackConn_list)

if __name__ == '__main__':
    d = date.Date()
    if len(sys.argv) > 1 and sys.argv[1] == "file":
        datetime_list = d.datetimeFromFile(sys.argv[2],minute_interval)
    elif len(sys.argv) > 1:
        datetime_list = d.datetimeFromTime(sys.argv[1], sys.argv[2],
                                                               minute_interval)
    else:
        datetime_list = d.datetimeNow(minute_interval)

    for start_datetime, end_datetime in datetime_list:
        print start_datetime
        monitorUnusedIP(start_datetime, end_datetime)
        monitorBlacklistIP(start_datetime, end_datetime)
