import MySQLdb
import sys
import os.path, ConfigParser

abs_dir = os.path.dirname(os.path.abspath(__file__))
config_path = abs_dir+"/setting.cfg"

class DB:
    def __init__(self, db):
        if os.path.isfile(config_path):
            cfg = ConfigParser.SafeConfigParser()
            cfg.read(config_path)
            if db in ["local", "noc"]:
                hostname = cfg.get(db, "host")
                username = cfg.get(db, "user")
                password = cfg.get(db, "password")
                database = cfg.get(db, "database")
                self.db = MySQLdb.connect(host=hostname, user=username, passwd=password, db=database)
            else:
                print "DB should be local/noc."
                sys.exit(1)
            self.cursor = self.db.cursor()
        else:
            print "Please set the setting.cfg file"
            sys.exit(1)
    
    def Execute(self, sql, data=None):
        return self.cursor.execute(sql, data)
    
    def Select(self, sql):
        self.cursor.execute(sql)
        return self.cursor.fetchall()

    def CloseDB(self):
        self.db.commit()
        self.cursor.close()
        self.db.close()
