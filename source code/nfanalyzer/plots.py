#!/usr/bin/python
#-*- coding: utf-8 -*-
import os
import sys
# The module we need
directory = os.path.dirname(os.path.abspath(__file__))
sys.path.append(directory+"/..")
import nflow
import date
import output
import iplist

# What the command should look like
# nfdump -R /nfs/netflow/2014-12-10/nfcapd.201412101301:nfcapd.201412101329
#                   -a -A srcip4/16 'src net 140.116.0.0/16' -o csv
def plots(start_datetime, end_datetime):
    nf = nflow.NetFlow()
    iplists = iplist.IPList()
    src_plain = nf.readLog(start_datetime, end_datetime, 1,
                           options=["-a", "-A", "srcip4/16", 
                                    iplists.getNetList("src")])
    src = nf.parseSummary(src_plain)
    srcbytes, srcflows, srcpackets = src['flows'], src['bytes'], src['packets']

    dst_plain = nf.readLog(start_datetime, end_datetime, 1,
                           options=["-a", "-A", "dstip4/16", 
                                    iplists.getNetList("dst")])
    dst = nf.parseSummary(dst_plain)
    dstbytes, dstflows, dstpackets = dst['flows'], dst['bytes'], dst['packets']
    
    outputer = output.Output(end_datetime=end_datetime)
    outputer.writePlot(srcbytes, srcflows, srcpackets, "src")
    outputer.writePlot(dstbytes, dstflows, dstpackets, "dst")

if __name__ == '__main__':
    minute_interval = 5
    d = date.Date()
    datetime_list = d.datetimeNow(minute_interval)

    for start_datetime, end_datetime in datetime_list:
        print start_datetime
        plots(start_datetime, end_datetime)
