import database

# Get the rules
class Rules:
    # init the structure of rules
    # {pattern:[event,threshold,srcip,srcport,dstip,dstport]}
    # pattern is like "TXTT"
    def __init__(self):
        self.rules={}

    # Get the max of the same src IP
    def getSsrcipMinThres(self):
        return min([v["threshold"] for k,v in \
                self.rules.iteritems() if k[0]=="T"])

    # Get rule from database
    def getRulesFromDB(self):
        local_db = database.DB("local")
        rules = local_db.Select("select * from rules;")
        for rule in rules:
            self.rules["".join(rule[4:8])] = \
                {"event":rule[1],"threshold":rule[2], "suprathreshold":rule[3]}
        local_db.CloseDB()
        return self.rules
