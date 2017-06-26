import database

class TrackList:
    def refreshTrackList(self, datetime):
        """
        Clean the outdated event in TrackList
        while events are over clearing threshold
        (under threshold over 1 hr)
        """
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        sql = "delete from tracklist where timediff('%s', stop_time)" \
                                " > CAST('01:00:00' AS TIME)" % datetime
        local_db.Execute(sql)

    def deleteTrackListItem(self, event):
        """
        Delete one item from TrackList
        """
        event_type, src_ip, src_port, dst_ip, dst_port = event[0:5]
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        sql = "delete from tracklist where event_type='%s' and src_ip='%s'" \
              " and src_port='%s' and dst_ip='%s' and dst_port='%s';" \
              % (event_type, src_ip, src_port, dst_ip, dst_port)
        local_db.Execute(sql)

    def updateTrackList(self, datetime, event): 
        """
        Update the event in TrackList
        If the event is out of threshold, then exports it
        (times of over threshold bigger than 30 times)
        Else update the TrackList in the db
        """
        event_type, src_ip, src_port, dst_ip, dst_port, count = event[0:6]
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        start_time, total_count, num = self.inTrackList(event)
        # The 30th times
        if num >= 29: 
            sql = "update tracklist set count=%d, num=%d, start_time='%s'," \
                  " stop_time='%s' where event_type='%s' and src_ip='%s'" \
                  " and src_port='%s' and dst_ip='%s' and dst_port='%s';" \
                  % (0, 0, datetime, datetime, event_type, \
                     src_ip, src_port, dst_ip, dst_port)
            local_db.Execute(sql)
            event[5] += total_count
            return start_time, event
        # If there is result
        elif start_time != "":
            sql = "update tracklist set count=%d,num=%d,stop_time='%s' " \
                  " where event_type='%s' and src_ip='%s' and src_port='%s' " \
                  " and dst_ip='%s' and dst_port='%s';" \
                  % (total_count+count, num+1, datetime, event_type, \
                     src_ip, src_port, dst_ip, dst_port)
        else:
            sql = "insert into tracklist (start_time, stop_time, event_type," \
                  " src_ip, src_port, dst_ip, dst_port, count, num) values "  \
                  "('%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, 1)"         \
                  % (datetime, datetime, event_type, \
                     src_ip, src_port, dst_ip, dst_port, count)
        local_db.Execute(sql)
        return "",None

    def inTrackList(self, event):
        """
        Check whether one event in TrackList and return count
        """
        event_type, src_ip, src_port, dst_ip, dst_port = event[0:5]
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        sql = "select * from tracklist where event_type='%s' and src_ip='%s'" \
              " and src_port='%s' and dst_ip='%s' and dst_port='%s';"         \
              % (event_type, src_ip, src_port, dst_ip, dst_port)
        result = local_db.Select(sql)
        if result != ():
            return result[0][0], result[0][7], result[0][8]
        else:
            return "", 0, 0

    def cleanTrackList(self):
        """
        Clean all cache in TrackList
        """
        local_db = database.DB("local")
        local_db.Execute("SET NAMES 'utf8'")
        sql = "truncate table tracklist;"
        local_db.Execute(sql)
