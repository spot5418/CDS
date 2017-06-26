#!/usr/bin/env python
#-*- coding: utf-8 -*-

import re
import os
import sys
# The module we need
directory = os.path.dirname(os.path.abspath(__file__))
sys.path.append(directory+"/..")
import rule
import iplist
import date
import nflow
import output
import tracklist

minute_interval = 1

# Get rules
rule_handler = rule.Rules()
rules = rule_handler.getRulesFromDB()
ssrcip_min_thres = rule_handler.getSsrcipMinThres()
# Ignore ACK response
ACK = [22,23,53,80,110,443,1433,3306]
P2P = [4672,51413,6881,17788] #eMule, BT, BT, PPS
EXCEPT = [6633] #SDN
# Brute Force port
BF_ports = [22,110,3306,3389]

# Get white list
iplists = iplist.IPList()
whitelist = ",".join(iplists.whitelist)

def getDconnPort(start_datetime, end_datetime, minute_interval):
    DCONN = []
    ignore_port = []
    ignore_port.extend(ACK)
    outputer = output.Output(start_datetime, end_datetime)
    nf = nflow.NetFlow()
    # get the set of dst port where (srcip,dstip,dstport) over threshold
    plain = nf.readLog(start_datetime, end_datetime, minute_interval, \
                       options=["-A", "srcip,dstip,dstport", "-s",    \
                               "record/flows", "-n", "20", "-N"],     \
                       mode="fmt:%sa,%da,%dp,%fl")
    for line in nf.parseLogLine(plain, mode="fmt:%sa,%da,%dp,%fl"):
        if int(line["fl"]) > 1000:
            ignore_port.append(int(line["dp"]))

    # get the (dstip,dstport) without wellknown ports and the port below
    plain = nf.readLog(start_datetime, end_datetime, minute_interval,         \
                       options=["-A", "dstip,dstport", "-s", "record", "-n",  \
                                "20", "-N", "not port in %s" % ignore_port],  \
                       mode="fmt:%da,%dp,%fl")
    for line in nf.parseLogLine(plain, mode="fmt:%da,%dp,%fl"):
        if int(line["fl"]) > 1000:
            DCONN.append(int(line["dp"]))
            outputer.writeDconn(line["da"], line["dp"], line["fl"])
    return DCONN

def scanDetect(start_datetime, end_datetime):
    nf = nflow.NetFlow()
    # event_name, srcip, srcport, dstip, dstport, count, pattern
    events = []
    # Get Dconn port result
    DCONN = getDconnPort(start_datetime, end_datetime, minute_interval)
    plain = nf.readLog(start_datetime, end_datetime, minute_interval,        \
                       options=[" %s and not inet6 and not ip in [%s]"       \
                                " and not port in %s and not src port in %s" \
                                " and (proto tcp or proto udp)"              \
                                % (iplists.getIgnoreNet(), whitelist,        \
                                   P2P+DCONN+EXCEPT, ACK),                   \
                                "-A", "srcip,dstip,dstport,proto"],
                       mode="fmt:%sa,%da,%dp,%fl,%pr")
    srcip_dict = {}

    for line in nf.parseLogLine(plain, mode="%fmt:%sa,%da,%dp,%fl,%pr"):
        # Count the number of srcip
        try:
            srcip_dict[line['sa']].append((line['da'], line['dp'], line['pr']))
        except:
            srcip_dict[line['sa']] = [(line['da'], line['dp'], line['pr'])]
        
        # Checking "TXTT"
        if int(line['fl']) > rules["TXTT"]["threshold"]:
           events.append([rules["TXTT"]["event"], line['sa'], "X", \
                            line['da'], line['dp'], int(line['fl']), "TXTT"]) 
        elif int(line["fl"]) > rules["TXTL"]["threshold"] \
                                and int(line["dp"]) in BF_ports:
           # Start with 140.116. in both src, dst IP
           if line['sa'][0:8] == line['da'][0:8]:
               continue
           events.append([rules["TXTL"]["event"], line['sa'], "X", \
                            line['da'], line['dp'], int(line['fl']), "TXTL"]) 

    # Counting vertical and horizontal scan
    for ip in srcip_dict:
        # Get the list of dst IP
        ip_list = [(i[0],i[2]) for i in srcip_dict[ip]]
        # Get the list of dst port
        port_list = [(i[1],i[2]) for i in srcip_dict[ip]]

        # Check whether there is "TXFT" (horizontal scan)
        tmp_list = list(set(port_list))
        if len(port_list) - len(tmp_list) > rules["TXFT"]["threshold"]:
            for tmp in tmp_list:
                # To avoid P2P connection, check the distribution of dst IP
                # the # of max classA should be bigger than half of dst IP
                if "140.116." in ip:
                    classA_list = [i[0].split('.')[0] \
                                      for i in srcip_dict[ip] if i[1]==tmp[0]]
                    if len(classA_list)/2 > \
                         max([classA_list.count(i) for i in set(classA_list)]):
                        continue
                # Count the # of port
                num = port_list.count(tmp)
                if num > rules["TXFT"]["threshold"]:
                    events.append([rules["TXFT"]["event"], 
                                        ip, "X", "F", tmp[0], num, "TXFT"])

        # Check whether there is "TXTF" (vertical scan)
        tmp_list = list(set(ip_list))
        if len(ip_list) - len(tmp_list) > rules["TXTF"]["threshold"]:
            for tmp in tmp_list:
                # Count the # of IP
                num = ip_list.count(tmp)
                if num > rules["TXTF"]["threshold"]:
                    # Not in Taiwan and 
                    # No 1/10 of dst port is smaller than 2000 
                    if not iplists.inForeign([ip, tmp[0]]) and \
                            (num/10) > len([i for i in srcip_dict[ip] \
                                     if i[0]==tmp[0] and int(i[1])<2000]):
                        continue
                    events.append([rules["TXTF"]["event"], 
                                        ip, "X", tmp[0], "F", num, "TXTF"])

    return events

def trackEvents(start_datetime, end_datetime, events):
    alert_events = []
    track_list = tracklist.TrackList()
    track_list.refreshTrackList(end_datetime)
    for event in events:
        # Avoid web access from NAT (Horizontal Scan)
        if iplists.allInternal([event[1]]) and event[4] in ["80","443"] and \
                event[6] == "TXFT" and event[5] < 10000:
            continue
        if event[5] > rules[event[6]]["suprathreshold"]:
            track_list.deleteTrackListItem(event)
            alert_events.append(event)
        else:
            # Avoid normal DNS query (Maybe NAT)
            if event[6] == "TXTT" and event[4] == "53":
                continue
            start_time, event = track_list.updateTrackList(end_datetime, event)
            if event != None:
                output_track = output.Output(start_time, end_datetime)
                #output_track.writeAnomalyFile([event])
                output_track.writeAnomalyDB([event])
    # Output
    output_alert = output.Output(start_datetime, end_datetime)
    #output_alert.writeAnomalyFile(alert_events)
    output_alert.writeAnomalyDB(alert_events)

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
        events = scanDetect(start_datetime, end_datetime)
        print events
        trackEvents(start_datetime, end_datetime, events)
