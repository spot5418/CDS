#!/usr/bin/env python
# -*- coding:utf-8 -*-

import os
import sys
# The module we need
directory = os.path.dirname(os.path.abspath(__file__))
sys.path.append(directory+"/..")
import date
import nflow
import output
import iplist

port_list=[53,123,161,1900]
minute_interval = 60

iplists = iplist.IPList()
dns_filter = iplists.getIgnoreDNS()

def DRDoSDetect(start_datetime, end_datetime):
    for port in port_list:
        if port == 53:
            proto_filter = dns_filter 
        else:
            proto_filter = ""
        # format: {(vul_ip,target_ip): [#flows, total_bytes]}
        statistics_to_port = {}
        statistics_from_port = {}
        nf = nflow.NetFlow()
        plain = nf.readLog(start_datetime, end_datetime, 1,
                           options=["port %d and not ip 239.255.255.250"     \
                                    " and not (src port %d and dst port %d)" \
                                    " and inet and proto udp %s"             \
                                    % (port, port, port, proto_filter)])
        for line in nf.parseLogLine(plain):
            if line["sp"] == str(port):
                stat_tuple = (line["sa"],line["da"])
                if stat_tuple not in statistics_from_port \
                                     and iplists.allInternal([line["sa"]]):
                    statistics_from_port.update({stat_tuple: \
                                      [1,int(line["ibyt"])+int(line["obyt"])]})
                elif iplists.allInternal([line["sa"]]):
                    statistics_from_port[stat_tuple][0] += 1
                    statistics_from_port[stat_tuple][1] += \
                                            int(line["ibyt"])+int(line["obyt"])
            elif line["dp"] == str(port):
                stat_tuple = (line["da"],line["sa"])
                if stat_tuple not in statistics_to_port \
                                        and iplists.allInternal([line["da"]]):
                    statistics_to_port.update({stat_tuple: \
                                      [1,int(line["ibyt"])+int(line["obyt"])]})
                elif iplists.allInternal([line["da"]]):
                    statistics_to_port[stat_tuple][0] += 1
                    statistics_to_port[stat_tuple][1] += \
                                            int(line["ibyt"])+int(line["obyt"])
            
        # set
        from_port = set(statistics_from_port.keys())
        to_port = set(statistics_to_port.keys())
        # and set
        and_set = from_port & to_port
        
        vul_iplist = set()
        # suspicious_vulnerable_ip: target_ip
        sus_vul_ips = {}
        # suspicious_target_ip: vulnerable_ip
        sus_target_ips = {}
        for item in and_set:
           # ratio
           from_byte = statistics_from_port[item][1]
           from_flow = statistics_from_port[item][0]
           to_byte = statistics_to_port[item][1]
           to_flow = statistics_to_port[item][0]
           from_ratio = from_byte / from_flow
           to_ratio = to_byte / to_flow
    
           if (from_ratio / to_ratio) > 3:
               # for vul ip
               if item[0] not in sus_vul_ips:
                   sus_vul_ips[item[0]] = [item[1]]
               else:
                   sus_vul_ips[item[0]].append(item[1])
               # for target ip
               if item[1] not in sus_target_ips:
                   sus_target_ips[item[1]] = [item[0]]
               else:
                   sus_target_ips[item[1]].append(item[0])
        for ip in sus_vul_ips:
            if len(sus_vul_ips[ip]) > 1:
                vul_iplist.add(ip)
        for ip in sus_target_ips:
            if len(sus_target_ips[ip]) > 1:
                vul_iplist |= set(sus_target_ips[ip])

        output_handler = output.Output(start_datetime=start_datetime)
        for IP in vul_iplist:
            output_handler.writeDRDoS(IP, port)

def spamDetect(start_datetime, end_datetime):
    output_handler = output.Output(start_datetime)
    nf = nflow.NetFlow()
    plain = nf.readLog(start_datetime, end_datetime, 1,
                       options=["-N", "-s", "srcip/flows", "dst port 25"])
    for line in nf.parseLogLine(plain):
        if int(line["fl"]) > 1000:
            output_handler.writeSpam(line["val"], int(line["fl"]))

def aflowDetect(start_datetime, end_datetime):
    output_handler = output.Output(start_datetime)
    nf = nflow.NetFlow()
    plain = nf.readLog(start_datetime, end_datetime, 1,
                       options=["-N", "-A", "proto,srcip,dstip,dstport", 
                                "-s", "record/bytes", "-L", "5G",
                                "inet and proto udp and not net 10.0.0.0/8" \
                                " and not ip 140.116.49.6 and" \
                                " not port in [3389]"],
                       mode="fmt:%sa,%da,%dp,%byt,%fl")
    for line in nf.parseLogLine(plain, mode="fmt:%sa,%da,%dp,%byt,%fl"):
        if int(line["fl"]) > 5:
            output_handler.writeAflow(start_datetime, 
                                      line["sa"], line["da"],
                                      line["dp"], line["byt"],
                                      line["fl"])

def scanDetect(start_datetime, end_datetime):
    """
    We only detect the following scan: 22,23,139,445,3389
    """
    port_statistics = {}
    output_handler = output.Output(start_datetime)
    nf = nflow.NetFlow()
    plain = nf.readLog(start_datetime, end_datetime, 1,
                        options=["-N", "-s", "record/flows", "-n", "0", \
                                 "-A", "srcip,dstip,dstport",     \
                                 "inet and not net 10.0.0.0/8 and "     \
                                 " port in [22,23,139,445,3389]"],      \
                        mode="fmt:%sa,%dp")
    for line in nf.parseLogLine(plain, mode="fmt:%sa,%dp"):
        item = (line["sa"], line["dp"])
        if item in port_statistics:
            port_statistics[item] += 1
        else:
            port_statistics[item] = 0
    for tuples,count in port_statistics.iteritems():
        if count > 300:
            output_handler.writeScan(tuples[0], tuples[1], count)

if __name__=='__main__':
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
        spamDetect(start_datetime, end_datetime)
        DRDoSDetect(start_datetime, end_datetime)
        aflowDetect(start_datetime, end_datetime)
        scanDetect(start_datetime, end_datetime)
