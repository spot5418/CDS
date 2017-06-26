from datetime import datetime, timedelta
import time

if hasattr(datetime, 'strptime'):
    # python 2.6
    strptime = datetime.strptime
else:
    # python 2.4 equivalent
    strptime = lambda date_string, format: \
            datetime(*(time.strptime(date_string, format)[0:5]))

class Date:
    def datetimeNow(self, minute_interval=1):
        """ 
        Output the start and end time where end time is now 
        and start time is minute_interval ago
        """
        delta = datetime.today().minute % minute_interval + minute_interval
        end_datetime = datetime(datetime.today().year,
                                datetime.today().month,
                                datetime.today().day,
                                datetime.today().hour,
                                datetime.today().minute) - timedelta(minutes=delta)
        start_datetime = end_datetime - timedelta(minutes=minute_interval)
        return [(start_datetime, end_datetime)]

    def datetimeFromFile(self, file_name, minute_interval=1):
        """
        Read start and end datetime from file_name, and return the list of 
        datetime tuples with minute_interval
        Format in file:
        start_datetime,end_datetime
        """
        datetimeList = []
        f = open(file_name)
        for line in f:
            line = line.strip()
            start_datetime = strptime(line.split(",")[0], "%Y-%m-%d %H:%M")
            end_datetime = strptime(line.split(",")[1], "%Y-%m-%d %H:%M")
            tmp_datetime = start_datetime
            while tmp_datetime < end_datetime:
                datetimeList.append((tmp_datetime,
                              tmp_datetime+timedelta(minutes=minute_interval)))
                tmp_datetime += timedelta(minutes=minute_interval)
        f.close()
        return datetimeList
    
    def datetimeFromTime(self, start_datetimeS, 
                         end_datetimeS, minute_interval=1):
        """ 
        Output the list of start and end time with the given minute_interval
        where start_time is start_datetimeS and end_time is end_datetimeS
        """
        start_datetime = strptime(start_datetimeS, "%Y-%m-%d %H:%M")
        end_datetime = strptime(end_datetimeS, "%Y-%m-%d %H:%M")
        datetimeList = []
        tmp_datetime = start_datetime
        while tmp_datetime < end_datetime:
            datetimeList.append((tmp_datetime,
                              tmp_datetime+timedelta(minutes=minute_interval)))
            tmp_datetime += timedelta(minutes=minute_interval)
        return datetimeList

    def datetimeYesterday(self):
        today = datetime.now()
        yesterday = today - timedelta(days=1)
        start_datetime = datetime(yesterday.year,
                                  yesterday.month,
                                  yesterday.day,
                                  0,0)
        end_datetime = datetime(today.year,
                                today.month,
                                today.day,
                                0,0)
        yesterday_date = yesterday.date()

        return (yesterday_date, start_datetime, end_datetime)

    def datetimeLastMonth(self):
        today = datetime.now()
        if today.month != 1:
            start_date = datetime(today.year,
                                  today.month - 1,
                                  1,0,0)
        else:
            start_date = datetime(today.year - 1,
                                  12,
                                  1,0,0)

        end_date = datetime(today.year,
                            today.month,
                            1,0,0)

        date_list = []
        while start_date.date() != end_date.date():
            date_list.append(start_date)
            start_date += timedelta(days=1)

        return date_list
