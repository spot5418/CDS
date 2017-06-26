import re
import subprocess
import socket
import struct
from datetime import datetime, timedelta
import config

"""
Netflow dump output format
    %ts   Start Time - first seen
    %te   End Time - last seen
    %td   Duration
    %pr   Protocol
    %sa   Source Address
    %da   Destination Address
    %sap  Source Address:Port
    %dap  Destination Address:Port
    %sp   Source Port
    %dp   Destination Port
    %sas  Source AS
    %das  Destination AS
    %in   Input Interface num
    %out  Output Interface num
    %pkt  Packets
    %byt  Bytes
    %fl   Flows
    %pkt  Packets
    %flg  TCP Flags
    %tos  Tos
    %bps  bps - bits per second
    %pps  pps - packets per second
    %bpp  bps - Bytes per package
"""

# Usage: 
class NetFlow(object):

    re_ipv4 = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." \
              "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." \
              "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." \
              "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

    def __init__(self):
        pass

    def readLog(self, start_datetime, end_datetime, log_interval, 
                options=[], file_name="", mode="csv"):
        end_datetime -= timedelta(minutes=log_interval)
        start_date = datetime.strftime(start_datetime.date(), "%Y-%m-%d")
        end_date = datetime.strftime(end_datetime.date(), "%Y-%m-%d")
        start_datetime = datetime.strftime(start_datetime, "%Y%m%d%H%M")
        end_datetime = datetime.strftime(end_datetime, "%Y%m%d%H%M")
        log_path = "%s%s/nfcapd.%s:%s/nfcapd.%s" % (config.nfs_dir, \
                   start_date, start_datetime, end_date, end_datetime)
        args = ['nfdump', '-R', log_path]
        # options
        args.extend(options)
        # mode
        args.extend(["-o", mode])

        if file_name == "":
            p = subprocess.Popen(args,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            out, err = p.communicate()
            return out
        else:
            file_handle = open(file_name, "w")
            p = subprocess.Popen(args,
                                 stdout=file_handle)
            ret_code = p.wait()
            file_handle.flush()
            file_handle.close()
            return ""

    def readDayLog(self, day, options=[], mode=""):
        day = datetime.strftime(day.date(), "%Y-%m-%d")
        log_path = "%s%s" % (config.nfs_dir, day)
        args = ['nfdump', '-R', log_path]
        # options
        args.extend(options)
        # mode
        args.extend(["-o", mode])
        p = subprocess.Popen(args,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        return out

    def parseLogLine(self, plain="", mode="csv"):
        if mode == 'csv':
            log = plain.split("\n")
            # if we use -a and -L, remove the first line
            # "Byte limit: > 2000 bytes"
            if "limit" in log[0]:
                log.pop(0)
            head = log[0].split(',')

            for line in log[1:-4]:
                if "," not in line:
                    break
                yield dict(zip(head, line.split(',')))

        elif mode == 'pipe':
            head = [
                'af',   # Address Family
                'tfs',  # Time First Seen
                'mfs',  # msec First Seen
                'tls',  # Time First Seen
                'mls',  # msec First Seen
                'pr',   # Protocol
                'sa',   # Source Address
                'sp',   # Source Port
                'da',   # Destination Address
                'dp',   # Destination Port
                'sas',  # Source AS Number
                'das',  # Destination AS Number
                'in',   # Input Interface
                'out',  # Output Interface
                'flg',  # TCP Flag
                'tos',  # Type of Service
                'pkt',  # Packet
                'byt'   # Byte
            ]

            for line in plain.split('\n')[:-5]:
                data = line.split('|')
                if data[0] == '2':
                    # IPv4
                    data[11:15] = [socket.inet_ntoa(struct.pack('!L', \
                                                            int(data[14])))]
                    data[6:10] = [socket.inet_ntoa(struct.pack('!L', \
                                                            int(data[9])))]
                elif data[0] == '10':
                    # IPv6
                    data[11:15] = [socket.inet_ntop(socket.AF_INET6,
                                                    struct.pack('!LLLL', \
                                                    *(long(i) for i in \
                                                    data[11:15])))]
                    data[6:10] = [socket.inet_ntop(socket.AF_INET6,
                                                   struct.pack('!LLLL', \
                                                   *(long(i) for i in \
                                                   data[6:10])))]
                else:
                    # Unknown
                    data[11:15] = [ "".join(data[11:15]) ]
                    data[6:10] = [ "".join(data[6:10]) ]

                yield dict(zip(head, data))
        else:
            head = [i.replace("%","") for i in mode.split(":")[1].split(",")]
            log = plain.split("\n")

            for line in log:
                if "Summary" in line:
                    break
                elif "," in line:
                    body = [i.strip() for i in line.split(',')]
                    yield dict(zip(head, body))

    def parseSummary(self, plain="", mode="csv"):
        log = plain.split("\n")
        if mode == 'csv':
            head = log[-3].split(',')
            return dict(zip(head, log[-2].split(',')))
        else:
            head = ["flows","bytes","packets"]
            pattern = "Summary: total flows: ([\d]+), total bytes: ([\d]+)," \
                      " total packets: ([\d]+)"
            result = list(re.findall(pattern, plain)[0])
            return dict(zip(head, result))

    def checkIPv4(self, ip=None):
        if ip is not None:
            return re.match(self.re_ipv4, ip)
