import MySQLdb, MySQLdb.cursors
import datetime, json, time
from python_lib import Singleton
from python_lib import Configs
import reverse_geocode

class DB(object):
    __metaclass__ = Singleton
    
    def __init__(self):
        
        self.dbLocation = Configs().get('dbLocation')
        
        if self.dbLocation == 'local':
            self.host   = 'localhost'
            self.user   = 'root'
            self.pw     = 'traffic'
            self.dbName = 'ResultsDB'
        
        self._connect()

    def _connect(self):
        self.conn = MySQLdb.connect(self.host, self.user, self.pw, self.dbName, 
                                    cursorclass=MySQLdb.cursors.DictCursor, 
                                    local_infile = 1,connect_timeout = 2,)
        self.cursor = self.conn.cursor()
        
#         self.execute('SET GLOBAL wait_timeout=2147483')
#         self.execute('SET GLOBAL interactive_timeout=2147483')
#         self.execute('SET GLOBAL local_infile=1;')
#         self.execute('SET wait_timeout=2147483;')

    def execute_wrapper(self, query):
        attempts = 0
        while attempts < 3:
            try:
                return self.execute(query)
            except Exception as e:
                code = e.args[0]
                if attempts == 2 or code != 2013:
                    raise e
                attempts += 1
                time.sleep(0.2 * attempts)

    def execute(self, query):
        #The following ping reconnects if connection has timed out 
        #(i.e. idle for more than wait_timeout which is a system variable of MySQL)
        self.conn.ping(True)
        time.sleep(1)
        # with open('SQL_LOG.txt','a') as sl:
        #     sl.writelines('\n' + query)
        self.cursor.execute(query)
        self.conn.commit()

    # (userID,historyCount,testID) should be the Primary Key in the table
    def insertResult(self, resObj, table= 'testResults', updateOnDup=True):
        columns = '(userID, historyCount, testID, extraString, date, replayName, xput_avg_original, xput_avg_test, area_test, ks2_ratio_test, ks2dVal, ks2pVal)'
        
        if updateOnDup:
            onDup = 'ON DUPLICATE KEY UPDATE area_test={}, ks2_ratio_test={}, xput_avg_original={}, xput_avg_test={}'.format(resObj.area_test, resObj.ks2_ratio_test, resObj.xput_avg_original, resObj.xput_avg_test)
        else:
            onDup = ''

        query   = ' '.join(['INSERT INTO', table, columns, 'VALUES', resObj.tuplify(), onDup, ';'])
        
        try:
            self.execute_wrapper(query)
        except Exception as e:
            print 'Exception in insertResult:', e
            # with open('SQL_EXC.txt','a') as sl:
            #     sl.writelines('\n' + str(e) + ':\n' + query)
    
    def insertReplay(self, to_write, instanceID, table='testReplays'):
        tmp          = to_write.split('\t')
        incomingTime = str(datetime.datetime.strptime(tmp[0], "%Y-%b-%d-%H-%M-%S"))
        # Get rid of the timestamps of the replayName
        if tmp[4] == 'AmazonAug8':
            tmp[4] = 'Amazon-Aug8'
        elif tmp[4] == 'AmazonAug8Random':
            tmp[4] = 'AmazonRandom-Aug8'
        elif tmp[4] == 'NetflixSep22':
            tmp[4] = 'Netflix-Sep22'
        elif tmp[4] == 'NetflixSep22Random':
            tmp[4] = 'NetflixRandom-Sep22'
        toInsert     = [incomingTime] + tmp[1:9]
        exceptions   = tmp[8]
        
        if exceptions in ['NoPermission', 'UnknownReplayName']:
            columns = '(instanceID, incomingTime, userID, id, clientIP, replayName, extraString, historyCount, testID, exceptions)'
        
        else:
            # toInsert += tmp[9:14]
             
            try:
                mobileStats = json.loads(tmp[14])
            except Exception as e:
                mobileStats = None
             
            if mobileStats is not None:
                # Get the country name via lat,lon

                lat = str(mobileStats['locationInfo']['latitude'])
                lon = str(mobileStats['locationInfo']['longitude'])
                if lat != '0.0' and lon != '0.0' and lat != 'nil':
                    coordinates = (float("{0:.2f}".format(float(lat))), float("{0:.2f}".format(float(lon)))), (
                        float("{0:.2f}".format(float(lat))), float("{0:.2f}".format(float(lon))))
                    country = reverse_geocode.search(coordinates)[0]['country']
                    toInsert += map(str,
                                [mobileStats['locationInfo']['latitude'],
                                 mobileStats['locationInfo']['longitude'],
                                 country,
                                 mobileStats['carrierName'],
                                 mobileStats['cellInfo'],
                                 mobileStats['networkType'],
                                 mobileStats['model'],
                                 mobileStats['os']['RELEASE'],
                                 mobileStats['os']['SDK_INT'],
                                 mobileStats['os']['INCREMENTAL'],
                                 mobileStats['manufacturer'],
                                 ])
                    columns = '(instanceID, incomingTime, userID, id, clientIP, replayName, extraString, historyCount, testID, exceptions, lat, lon, country, carrierName, cellInfo, networkType, model, rel, sdkInt, incremental, manufacturer)'
                else:
                    toInsert += map(str,
                                [mobileStats['locationInfo']['latitude'],
                                 mobileStats['locationInfo']['longitude'],
                                 mobileStats['carrierName'],
                                 mobileStats['cellInfo'],
                                 mobileStats['networkType'],
                                 mobileStats['model'],
                                 mobileStats['os']['RELEASE'],
                                 mobileStats['os']['SDK_INT'],
                                 mobileStats['os']['INCREMENTAL'],
                                 mobileStats['manufacturer'],
                                 ])
                    columns = '(instanceID, incomingTime, userID, id, clientIP, replayName, extraString, historyCount, testID, exceptions, lat, lon, carrierName, cellInfo, networkType, model, rel, sdkInt, incremental, manufacturer)'

            else:
                columns = '(instanceID, incomingTime, userID, id, clientIP, replayName, extraString, historyCount, testID, exceptions)'
        
        toInsert = [instanceID] + toInsert
        
        query = ' '.join(['INSERT INTO', table, columns, 'VALUES', str(tuple(toInsert)), ';'])


        try:
            self.execute_wrapper(query)
            return True
        except Exception as e:
            print 'Exception in insertReplays:', e
            return (e, query)
            # with open('SQL_EXC.txt','a') as sl:
            #     sl.writelines('\n' + str(e) + ':\n' + query)

    #  (userID,historyCount,testID) as Primary Key, should uniquely identify a replay
    def getSingleResult(self, userID, historyCount, testID, table = 'testResults'):
        query = "SELECT * FROM " + table + " WHERE userID='{}' ".format(userID)

        query += 'AND historyCount = {} AND testID = {}'.format(historyCount, testID)
        try:
            self.execute_wrapper(query)
            results = self.cursor.fetchall()
        except Exception as e:
            print '\r\n ERROR in getting result', e
            results = ()
        return results

    def getMultiResults(self, userID, maxHistoryCount=None, limit=None):
        
        if limit is None:
            limit = 10
        
        query = "SELECT * FROM testResults WHERE userID='{}' ".format(userID)
        
        if isinstance( maxHistoryCount, int ):
            query += ' AND {} < historyCount AND historyCount <= {} '.format(maxHistoryCount-limit, maxHistoryCount)
        else:
            query += ' ORDER BY historyCount DESC LIMIT {}; '.format(limit)
        
        self.execute_wrapper(query)
        results = self.cursor.fetchall()
        return results
    
    def getStats(self):
        usersStats    = {}
        replayStats   = {}
        detailedStats = {}
        resultsStats  = {}
        
        #Get number of unique userIDs
        query = 'SELECT COUNT(DISTINCT userID) as c FROM ResultsDB.replays;'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        usersStats['#unique userIDs'] = res[0]['c']
        
        #Get number of replays
        query = 'SELECT COUNT(*) as c FROM ResultsDB.replays;'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        replayStats['#replays'] = res[0]['c']
        
        #Test break down
        query = 'SELECT COUNT(*) as c FROM ResultsDB.replays WHERE testID LIKE \'NOVPN_%\';'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        replayStats['#replays-NOVPN'] = res[0]['c']
        
        query = 'SELECT COUNT(*) as c FROM ResultsDB.replays WHERE testID LIKE \'VPN_%\';'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        replayStats['#replays-VPN'] = res[0]['c']
        
        query = 'SELECT COUNT(*) as c FROM ResultsDB.replays WHERE testID LIKE \'RANDOM_%\';'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        replayStats['#replays-RANDOM'] = res[0]['c']
        
        query = 'SELECT COUNT(*) as c FROM ResultsDB.replays WHERE testID LIKE \'SINGLE%\';'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        replayStats['#replays-SINGLE'] = res[0]['c']
        
        query = 'SELECT exceptions, COUNT(*) as c FROM ResultsDB.replays GROUP BY exceptions;'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        replayStats['exceptions'] = {}
        for r in res:
            replayStats['exceptions'][r['exceptions']] = r['c']
            
        query = 'SELECT carrierName, COUNT(*) as c FROM ResultsDB.replays GROUP BY carrierName;'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        replayStats['carrierName'] = {}
        for r in res:
            replayStats['carrierName'][r['carrierName']] = r['c']
        
        query = 'SELECT networkType, COUNT(*) as c FROM ResultsDB.replays GROUP BY networkType;'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        replayStats['networkType'] = {}
        for r in res:
            replayStats['networkType'][r['networkType']] = r['c']
        
        query = 'SELECT TRUNCATE(lon,0) as lonT, TRUNCATE(lat,0) as latT, COUNT(*) as c FROM ResultsDB.replays WHERE lon!=0 AND lon IS NOT NULL GROUP BY lonT, latT;'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        replayStats['locations'] = res
        
        #App break down
        query = 'SELECT COUNT(*) as c, replayName FROM ResultsDB.replays GROUP BY replayName;'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        for r in res:
            try:
                detailedStats[r['replayName'].partition('-')[0]] += r['c']
            except KeyError:
                detailedStats[r['replayName'].partition('-')[0]]  = r['c']

                
        #Results stats
        query = 'SELECT COUNT(*) as c FROM ResultsDB.results;'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        resultsStats['#tests'] = res[0]['c']
        
        query = 'SELECT COUNT(*) as c FROM ResultsDB.results WHERE area_vpn=-1 and area_random=-1;'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        resultsStats['#tests-failed'] = res[0]['c']
        
        #VPN no diff
        query = 'SELECT COUNT(*) as c FROM ResultsDB.results WHERE (area_vpn<=0.2 and ks2_ratio_vpn>=0.95);'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        resultsStats['#vpn-no-diff'] = res[0]['c']
        
        #VPN diff
        query = 'SELECT COUNT(*) as c FROM ResultsDB.results WHERE (area_vpn>0.2 and ks2_ratio_vpn<0.95);'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        resultsStats['#vpn-diff'] = res[0]['c']
        
        #VPN inconclusive
        query = 'SELECT COUNT(*) as c FROM ResultsDB.results WHERE (area_vpn<=0.2 and ks2_ratio_vpn<0.95) or (area_vpn>0.2 and ks2_ratio_vpn>=0.95);'
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        resultsStats['#vpn-inconclusive'] = res[0]['c']
        
        query = """
                SELECT rep.carrierName, rep.replayName, COUNT(*) as c FROM 
                (SELECT * FROM ResultsDB.results WHERE (area_vpn>0.2 and ks2_ratio_vpn<0.95)) AS res
                JOIN 
                (SELECT * FROM ResultsDB.replays GROUP BY userID, historyCount) AS rep
                ON (res.userID=rep.userID AND res.historyCount=rep.historyCount)
                GROUP BY rep.carrierName, rep.replayName;
                """
        self.execute_wrapper(query)
        res = self.cursor.fetchall()
        resultsStats['perNetwork'] = {}
        for r in res:
            try:
                resultsStats['perNetwork'][r['carrierName']]
                
            except KeyError:
                resultsStats['perNetwork'][r['carrierName']] = {'youtube':0, 'netflix':0, 'spotify':0, 'hangout':0, 'skype':0, 'viber':0}
                
            resultsStats['perNetwork'][r['carrierName']][r['replayName'].partition('-')[0].lower()] += r['c']
        
        
        return usersStats, replayStats, detailedStats, resultsStats
    
    def updateReplayXputInfo(self, resObj):
        xputInfos = resObj.replaysXputInfo
        rttInfos  = resObj.replaysRTTInfo
        for what in xputInfos:
            for testCount in xputInfos[what]:
#                 query = "UPDATE ResultsDB.replays SET xput_min={}, xput_max={}, xput_avg={} WHERE userID='{}' AND testID='{}_{}' AND historyCount={};".format(xputInfos[what][testCount]['min'],
#                                                                                                                                                          xputInfos[what][testCount]['max'],
#                                                                                                                                                          xputInfos[what][testCount]['avg'],
#                                                                                                                                                          resObj.userID,
#                                                                                                                                                          what, 
#                                                                                                                                                          testCount,
#                                                                                                                                                          resObj.historyCount)
                query = "UPDATE ResultsDB.replays SET xput_min={}, xput_max={}, xput_avg={}, rtt_min={}, rtt_max={}, rtt_avg={} WHERE userID='{}' AND testID='{}_{}' AND historyCount={};".format(xputInfos[what][testCount]['min'],
                                                                                                                                                                                                  xputInfos[what][testCount]['max'],
                                                                                                                                                                                                  xputInfos[what][testCount]['avg'],
                                                                                                                                                                                                  rttInfos[what][testCount]['min'],
                                                                                                                                                                                                  rttInfos[what][testCount]['max'],
                                                                                                                                                                                                  rttInfos[what][testCount]['avg'],
                                                                                                                                                                                                  resObj.userID,
                                                                                                                                                                                                  what, 
                                                                                                                                                                                                  testCount,
                                                                                                                                                                                                  resObj.historyCount)
                self.execute_wrapper(query)

                query = "UPDATE ResultsDB.replays SET rtt_min={}, rtt_max={}, rtt_avg={} WHERE userID='{}' AND testID='{}_{}' AND historyCount={};".format(xputInfos[what][testCount]['min'],
                                                                                                                                                         xputInfos[what][testCount]['max'],
                                                                                                                                                         xputInfos[what][testCount]['avg'],
                                                                                                                                                         resObj.userID,
                                                                                                                                                         what, 
                                                                                                                                                         testCount,
                                                                                                                                                         resObj.historyCount)
       
    def close(self):
        self.conn.close()
    
def main():
    db = DB()
    
#     print 'lor:', db.conn.open, type(db.conn.open)
#     db.execute('select * from results;')
#     
#     db.close()
#     print 'lor:', db.conn.open, type(db.conn.open)
#     
#     db.execute('select * from results;')
#     
#     print 'lor:', db.conn.open, type(db.conn.open)

if __name__=="__main__":
    main()
