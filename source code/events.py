#!/usr/bin/env python
#-*- coding: utf-8 -*-

import os
import sys
import datetime
import re
# The module we need
directory = os.path.dirname(os.path.abspath(__file__))
sys.path.append(directory)
import database
import config
# For Debugging
import pdb
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get the last hour
now = datetime.datetime.now()
stop_time = now - datetime.timedelta(minutes=5)
stop_time = datetime.datetime.strftime(stop_time, "%Y-%m-%d %H:%M:%S")
logging.debug("Now we read all the log after %s" % stop_time)

# Declare variable
anomaly_dic = {}
monIP_dic = {}
trackIP_list = []

def get_source(ip):
    source = ""
    warning = False
    # Neglect the IPv6
    if "." not in ip:
        return ""
    if "140.116." in ip:
        # Get the boss of IP
        f = re.findall("140\.116\.(\d+).(\d+)",ip)
        local_db = database.DB("noc")
        local_db.Execute("SET NAMES 'utf8'")
        result = local_db.Select("select Account from IP \
                where ClassC=\"%s\" and Host=\"%s\"" % (f[0][0],f[0][1]))
        logger.debug("Get EE source:"+str(result))
        if result != ():
            result = local_db.Select("select Name from Users \
                                    where Account='%s';" % result[0][0])
            warning = True
            try:
                source = result[0][0]
                local_db.CloseDB()
            except:
                local_db.CloseDB()
        else:
            source = "NCKU"
    # Get the country of IP
    #else:
        #ip_content = urllib.urlopen("http://freegeoip.net/json/"+ip)
        #json_struct = ip_content.read()
        #json_struct = json_struct.strip()
        #json_struct = simplejson.loads(json_struct)
        #source += json_struct['country_name']
    return (warning, source)

def main():
    # Read the log in the past hour
    local_db = database.DB("local")
    local_db.Execute("SET NAMES 'utf8'")
    sql = "select stop_time, src_ip from anomaly_log \
            where TIMESTAMP(stop_time)>='%s'" % stop_time
    result = local_db.Select(sql)
    for i in result:
        if i[1] not in ['X','F']:
            anomaly_dic.update({i[1]:i[0]})
    logging.debug("The list len from anomaly flow is %d" % len(anomaly_dic))
    
    sql = "select date, source from monIP_log \
            where TIMESTAMP(date)>='%s'" % stop_time
    result = local_db.Select(sql)
    for i in result:
        monIP_dic.update({i[1]:i[0]})
    logging.debug("The list len from monitored IP is %d" % len(monIP_dic))
    
    # Get the IP list and the last attack time
    ip_list = anomaly_dic.keys()
    ip_list.extend(i for i in monIP_dic.keys() if i not in ip_list)
    for ip in ip_list:
        if ip in anomaly_dic and ip in monIP_dic:
            if anomaly_dic[ip] > monIP_dic[ip]:
                lasttime = anomaly_dic[ip]
            else:
                lasttime = monIP_dic[ip]
        elif ip in anomaly_dic:
            lasttime = anomaly_dic[ip]
        elif ip in monIP_dic:
            lasttime = monIP_dic[ip]
        trackIP_list.append([ip,lasttime]) 
    logging.debug("The list len of IP is %d" % len(trackIP_list))
    
    # Get the IP metadata
    for item in trackIP_list:
        item += list(get_source(item[0]))
    
    # Save into database
    for item in trackIP_list:
        sql = "select last_attack from event_statistics where IP='%s'" \
                                                                    % item[0]
        result = local_db.Execute(sql)
        if result == 0:
            sql = "insert into event_statistics \
                    (IP, source, warning, last_attack) \
                    values ('%s', '%s', %r, '%s')" % \
                    (item[0], item[3], item[2], item[1]) 
        else:
            sql = "update event_statistics set last_attack='%s' where IP='%s'"\
                        % (item[1], item[0])
        local_db.Execute(sql)
    local_db.CloseDB()

if __name__=='__main__':
    main()
