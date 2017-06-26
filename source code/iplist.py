import database
import config
import GeoIP
import netaddr

# Check whether IP in the list
class IPList:
    def __init__(self):
        self.whitelist = []
        self.blacklist = []
        self.unusedIP = []
        self.tracklist = []
        
        # white list
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        results = local_db.Select("select * from whitelist;")
        for result in results:
            self.whitelist.append(result[0])
        # black list
        local_db.Execute("delete from blacklist where last_updated < " \
                         "ADDDATE(NOW(), INTERVAL -7 DAY)")
        results = local_db.Select("select * from blacklist;")
        for result in results:
            self.blacklist.append(result[0])
        # unused IP list
        results = local_db.Select("select * from unusedIP;")
        for result in results:
            self.unusedIP.append(result[0])
        # track list
        #local_db.Execute("delete from tracklist where last_updated < " \
        #                 " ADDDATE(NOW(), INTERVAL -1 HOUR)")
        #results = local_db.Select("select * from tracklist;")
        #for result in results:
        #    self.tracklist.append(result[0])

        local_db.CloseDB()

    # Get the netlist ip from file
    def getNetList(self, list_type = "list", version=4):
        if version != 6:
            file_handle = open(config.netlist)
        else:
            file_handle = open(config.netlist_v6)
        net_list = [net.strip() for net in file_handle]
        if list_type == "list":
            return net_list
        elif list_type == "src":
            return "src net "+" or src net ".join(net_list)
        elif list_type == "dst":
            return "dst net "+" or dst net ".join(net_list)
        file_handle.close()

    def addBlackList(self, ip, reason):
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        if ip in self.blacklist:
            sql = "update blacklist set reason='%s' where IP='%s';" % \
                    (reason, ip)
        else:
            sql = "insert into blacklist (IP,reason) values ('%s','%s')" % \
                    (ip, reason)
            self.blacklist.append(ip)
        local_db.Execute(sql)
        local_db.CloseDB()
    
    # return True if any ip in ip_list is blacklist
    def inBlackList(self, ip_list):
        check = False
        for ip in ip_list:
            if ip in self.blacklist:
                check = True
                break
        return check

    # return True if any ip in ip_list is whitelist
    def inWhiteList(self, ip_list):
        check = False
        for ip in ip_list:
            if ip in self.whitelist:
                check = True
                break
        return check

    # return True if any ip in ip_list is from Foreign
    def inForeign(self, ip_list):
        check = False
        gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
        for ip in ip_list:
            country = gi.country_code_by_name(ip)
            if country != "TW":
                check = True
                break
        return check

    # Only work for IPv4 right now
    # return True is all ip in ip_list is internal
    def allInternal(self, ip_list):
        file_handle = open(config.netlist)
        net_list = [netaddr.IPNetwork(net) for net in file_handle]

        check = True
        for ip in ip_list:
            for net in net_list:
                if netaddr.IPAddress(ip) in net:
                    check =True
                    break
                else:
                    check = False
            if check == False:
                break
        return check

    def getIgnoreNet(self):
        iplist = config.ignore_net.split(",")
        return "not net "+" and not net ".join(iplist)

    def getIgnoreDNS(self):
        iplist = config.ignore_dns.split(",")
        return " and not ip in ["+",".join(iplist)+"]"
