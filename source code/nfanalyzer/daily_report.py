#!/usr/bin/python
#-*- coding: utf-8 -*-
import os
import sys
# The module we need
directory = os.path.dirname(os.path.abspath(__file__))
sys.path.append(directory+"/..")
import date
import nflow
import config
import iplist

# What the command should look like
#nfdump -R /nfs/netflow/2014-12-11/nfcapd.201412110000:nfcapd.201412112359 
#-s srcip/packets -n 0 'dst port 21 and src net 140.116.0.0/16' -o csv

def report(yesterday, start_datetime, end_datetime):
    # Check report_dir
    report_dir = config.report_dir+str(yesterday)+"/"
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    nf = nflow.NetFlow()
    iplists = iplist.IPList()
    ip_proto = ""
    #for ipv4, ipv6
    for ip in [4,6]:
        for orderby in ["flows","packets","bytes"]:
            if ip != 4:
                ip_proto = "6"
            #for ICMP
            absname = report_dir+str(yesterday)+"_ICMP"+ip_proto+"_"+orderby
            nf.readLog(start_datetime, end_datetime, 1,
                       options=["-s", "srcip/"+orderby, "-n", \
                                "0", "proto icmp%s" % ip_proto],
                       file_name=absname)
            if ip != 4:
                ip_proto = "v6"

            # For port list
            for port in [21,22,23,25,53,80,135,139,443,445,3128,3389]:
                absname = "%s%s_port%d%s_%s" % \
                          (report_dir, str(yesterday), port, ip_proto, orderby)
                nf.readLog(start_datetime, end_datetime, 1,
                           options=["-s", "srcip/"+orderby, "-n", "0", \
                                    "dst port %s and (%s)" % \
                                    (str(port), iplists.getNetList("src",ip))],
                           file_name=absname)

            # For uplink
            absname = report_dir+str(yesterday)+"_uplink"+ip_proto+"_"+orderby
            nf.readLog(start_datetime, end_datetime, 1,
                       options=["-s", "srcip/"+orderby, "-n", "0", "%s" % \
                                iplists.getNetList("src",ip)],
                       file_name=absname)

            # For downlink
            absname = "%s%s_downlink%s_%s" % \
                      (report_dir, str(yesterday), ip_proto, orderby)
            nf.readLog(start_datetime, end_datetime, 1,
                       options=["-s", "dstip/"+orderby, "-n", "0", "%s" % \
                                iplists.getNetList("dst",ip)],
                       file_name=absname)

if __name__ == '__main__':
    d = date.Date()
    yesterday, start_datetime, end_datetime = d.datetimeYesterday()
    report(yesterday, start_datetime, end_datetime)
