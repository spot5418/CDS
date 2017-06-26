import database
import config
import iplist

class Output:
    def __init__(self, start_datetime=None, end_datetime=None):
        self.start_datetime = start_datetime
        self.end_datetime = end_datetime

    def writeScan(self, srcip, dstport, count):
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        sql = "insert into scan_log (datetime,src_ip,dst_port,count) \
               values ('%s', '%s', '%s', %d)" % \
               (self.start_datetime, srcip, dstport, count)
        local_db.Execute(sql)
        local_db.CloseDB()

    def writeDconn(self, IP, port, flows):
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        sql = "select * from Dconn_log where IP='%s' and port=%s" % (IP, port)
        result = local_db.Select(sql)
        if result != ():
            sql = "update Dconn_log set flows=%s where IP='%s'"  \
                  " and port=%s" % (flows, IP, port)
        else:
            sql = "insert into Dconn_log (flows, IP, port) values" \
                  " (%s, '%s', %s)" % (flows, IP, port)
        local_db.Execute(sql)
        local_db.CloseDB()

    def writeAflow(self, datetime, srcip, dstip, dstport, byts, flows):
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        sql = "insert into aflow_log (datetime, src_ip, dst_ip, dst_port," \
              " bytes, flows) values ('%s', '%s', '%s', %s, %s, %s)" % \
              (datetime, srcip, dstip, dstport, byts, flows)
        local_db.Execute(sql)
        local_db.CloseDB()

    def writeSpam(self, IP, flows):
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        sql = "insert into spam_log (datetime, IP, flows) values" \
              " ('%s', '%s', %d)" % (str(self.start_datetime), IP, flows)
        local_db.Execute(sql)
        local_db.CloseDB()
        
    def writeDRDoS(self, IP, port):
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        sql = "select * from DRDoS_log where IP='%s' and port=%d" % (IP, port)
        result = local_db.Select(sql)
        if result != ():
            sql = "update DRDoS_log set datetime='%s' where IP='%s'"  \
                  " and port=%d" % (str(self.start_datetime), IP, port)
        else:
            sql = "insert into DRDoS_log (datetime, IP, port) values" \
                  " ('%s', '%s', %d)" % (str(self.start_datetime), IP, port)
        local_db.Execute(sql)
        local_db.CloseDB()

    def writeAnomalyFile(self, events):
        iplist_handler = iplist.IPList()
        file_handler = open(config.anomaly_log,"aw")
        file_handler.write("%s -> %s\n" % \
                           (str(self.start_datetime),
                            str(self.end_datetime))
                          )
        for event in events:
            # see if in whitelist 
            if iplist_handler.inWhiteList([event[1],event[3]]):
                continue
            file_handler.write("%s: %s:%s -> %s:%s  (%d)\n" % \
                       (event[0],event[1],event[2],event[3],event[4],event[5]))
        file_handler.close()
        
    # event_name, srcip, srcport, dstip, dstport, count
    def writeAnomalyDB(self, events):
        iplist_handler = iplist.IPList()
        # Writing into database
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        # For each event
        for event in events:
            # update blacklist
            if len(event[1]) > 2:
                iplist_handler.addBlackList(event[1], event[0])
            # Update anomaly_log table
            timestamp = ""
            sql = "select * from anomaly_log where stop_time='%s'"           \
                  " and event_type='%s' and src_ip='%s' and src_port='%s'"   \
                  " and dst_ip='%s' and dst_port='%s';" %                    \
                    (self.start_datetime, event[0], event[1],                \
                     event[2], event[3], event[4]);
            result = local_db.Select(sql)
            # If the log exists
            if result != ():
                timestamp = str(result[0][1])[:-3]
                sql = "update anomaly_log set stop_time='%s',"              \
                      " attack_count=%d where stop_time='%s' and"           \
                      " event_type='%s' and src_ip='%s' and src_port='%s'"  \
                      " and dst_ip='%s' and dst_port='%s';" %               \
                      (self.end_datetime, event[5]+int(result[0][8]),       \
                       self.start_datetime, event[0], event[1], event[2],   \
                       event[3], event[4])
            # If this is a new log
            else:
                timestamp = self.start_datetime
                sql = "insert into anomaly_log (start_time, stop_time,"     \
                      " event_type, src_ip, src_port, dst_ip, dst_port,"    \
                      " attack_count) values"                               \
                      " ('%s','%s','%s','%s','%s','%s','%s',%d);" %         \
                        (self.start_datetime, self.end_datetime, event[0],  \
                         event[1], event[2], event[3], event[4], event[5])
            local_db.Execute(sql)
        local_db.CloseDB()

    def writeMonIPLog(self, monIP_list):
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        for l in monIP_list:
            sql_stmt = "INSERT IGNORE INTO monIP_log "              \
                       " (source, srcport, target, dstport, date) " \
                       " VALUES (%s, %s, %s, %s, %s)"
            sql_data = (l['source'],l['srcport'],l['target'], \
                        l['dstport'],l['date'])
            local_db.Execute(sql_stmt, sql_data)
        local_db.CloseDB()

    def writeBlackList(self, blackConn_list):
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        for l in blackConn_list:
            sql_stmt = "INSERT IGNORE INTO blacklist_log "            \
                       " (src_ip, dst_ip, src_port, dst_port, date) " \
                       "VALUES (%s, %s, %s, %s, %s)"
            sql_data = (l['src_ip'], l['dst_ip'], \
                        l['src_port'], l['dst_port'], l['date'])
            local_db.Execute(sql_stmt, sql_data)
        local_db.CloseDB()

    def writePlot(self, flow, byte, packet, identity):
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        sql = "insert into plots (date, flows, bytes, packets, identity) "\
                                 "values ('%s', %s, %s, %s, '%s');" % \
                              (self.end_datetime, flow, byte, packet, identity)
        local_db.Execute(sql)
        local_db.CloseDB()

    def writePortStatistics(self, month, protocol, port, flows):
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        sql = "insert into port_statistics (month, protocol, port, flows) "\
                                           "values ('%s', %s, %s, %s);" % \
                                           (month, protocol, port, flows)
        local_db.Execute(sql)
        local_db.CloseDB()

    def writeTraffic(self, srcIP, srcport, dstIP, dstport, protocol, bytes):
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        # Check whether the log exists
        sql = "select bytes from traffic where stop_time='%s'"           \
                                 " and srcip = '%s' and srcport = '%s'"  \
                                 " and dstip = '%s' and dstport = '%s';" \
                                 % (self.start_datetime, srcIP,          \
                                    srcport, dstIP, dstport)
        result = local_db.Select(sql)
        if result != ():
            sql = "update traffic set stop_time='%s', bytes=%d "         \
                                  "where stop_time='%s'"                 \
                                  "and srcip='%s' and srcport='%s'"      \
                                  "and dstip='%s' and dstport='%s';"     \
                                  % (self.end_datetime,      \
                                     int(result[0][0])+bytes, \
                                     self.end_datetime,      \
                                     srcIP, srcport,          \
                                     dstIP, dstport)
        else: 
            sql = "insert into traffic (srcip, srcport, dstip,           \
                                        dstport, proto, bytes,           \
                                        start_time, stop_time)           \
                                        values ('%s','%s','%s',          \
                                        '%s','%s', %d, '%s', '%s');"     \
                                        % (srcIP, srcport,      \
                                           dstIP, dstport,      \
                                           protocol, bytes,     \
                                           self.start_datetime, \
                                           self.end_datetime)
        local_db.Execute(sql)
        local_db.CloseDB()
