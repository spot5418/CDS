#!/usr/bin/env python
#-*- coding: utf-8 -*-

import os
import sys
import datetime
# The module we need
directory = os.path.dirname(os.path.abspath(__file__))
sys.path.append(directory+"/..")
import nflow
from common import *
from output import *

# rules
rules = [("FTP", 21, 2000),
        ("SSH", 22, 10000),
        ("TELNET", 23, 100000),
        ("RDP", 3389, 40000000)]

# EX: If now is 5:15, then it should be 05:10:00->05:14:59 (nfcapd 0510:0514)
now = datetime.datetime.now()
delta = now.minute % 5
end_datetime = now - datetime.timedelta(minutes=delta)
real_end_datetime = now - datetime.timedelta(minutes=(delta+1))
start_datetime = end_datetime - datetime.timedelta(minutes=5)

# What the command should look like
# nfdump -R /nfs/netflow/2015-03-09/nfcapd.201503091730:nfcapd.201503091735
#                   -a 'port in [21]' -L 500 -o csv
def main():
    output = Output(start_datetime, end_datetime)
    checkIP = IPchecker()
    nf = nflow.NetFlow()
    for rule in rules:
        plain = nf.readLog(start_datetime, real_end_datetime,
                           options=["-a", "-L", "%d" % rule[2],
                                    "port %s" % rule[1]])
        for line in nf.parseLogLine(plain):
            if checkIP.inWhiteList([ line['sa'],line['da'] ]):
                continue
            elif checkIP.AllInternal([ line['sa'],line['da'] ]):
                continue
            srcIP, srcport, dstIP, dstport = line['sa'], line['sp'], \
                                             line['da'], line['dp']
            bytes = int(line['obyt']) + int(line['ibyt'])
            protocol = line['pr']
            output.writeTraffic(srcIP, srcport, \
                                dstIP, dstport, \
                                protocol, bytes)

if __name__ == '__main__':
    main()
