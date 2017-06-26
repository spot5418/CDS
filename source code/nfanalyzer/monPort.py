#!/usr/bin/env python
import os
import sys
# The module we need
directory = os.path.dirname(os.path.abspath(__file__))
sys.path.append(directory+"/..")
import date
import output
import nflow
import iplist

nf = nflow.NetFlow()
ip_list = iplist.IPList()
unusedIP_list = ip_list.unusedIP
d = date.Date()
date_list =  d.datetimeLastMonth()

outputer = output.Output()

rule_filter =[]
for ip in unusedIP_list:
    rule_filter.append("dst ip %s" % ip)
rule_filter = "not src net 140.116.0.0/16 and ( "+" or ".join(rule_filter)+" )"
# CMD can't have such a long rules
f = open("rule.list", "w")
f.write(rule_filter)
f.close()

start_date = date_list[0]
# Add the flag to notify the end of datalist
date_list.append("end")
# statistics_0day = {("6","80"):v1, ("17","1900"):v2}
statistics_0day = {}
for date_time in date_list:
    # New month and print statistics
    if str(date_time) == "end" or date_time.month != start_date.month:
        for item,flows in sorted(statistics_0day.iteritems(), \
                                 key=lambda x : x[1], reverse=True):
            if flows > 10:
                # Output to db
                # month, proto, port, flows
                outputer.writePortStatistics(start_date,item[0],item[1],flows)
        start_date = date_time
        statistics_0day = {}

    # Lost data
    if not os.path.isdir("/nfs/netflow/%s" % str(date_time)[0:10]):
        continue

    print date_time.date()
    plain = nf.readDayLog(date_time,                                      \
                          options=["-A", "proto,dstport", "-s", "record", \
                                   "-N", "-n", "0", "-f", "rule.list"],   \
                          mode="fmt:%pr,%dp,%fl")
    if plain == "":
        continue

    for line in nf.parseLogLine(plain, mode="fmt:%pr,%dp,%fl"):
        item = (line["pr"], line["dp"])
        if item in statistics_0day:
            statistics_0day[item] += int(line["fl"])
        else:
            statistics_0day[item] = int(line["fl"])

f.close()
