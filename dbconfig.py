import pymysql
import configparser


class MysqlController:
    def __init__(self):
        parser = configparser.ConfigParser()
        parser.read('connecter.conf')
        self.conn = pymysql.connect(host=parser.get('db', 'host'), user=parser.get('db', 'id'),
                                    password=parser.get('db', 'pw'),
                                    db=parser.get('db', 'db_name'), charset='utf8',
                                    cursorclass=pymysql.cursors.DictCursor)
        self.curs = self.conn.cursor()

    def createReq(self, processUUID: str, hostURL: str, count: int, URIs: str, state: str):
        try:
            if count > 100:
                URIs = 'OVER 100'
            sql = "insert into IF_DICOMLINK_REQ (process_uuid, host_url, count, uris, state, create_dt) values (%s, %s, %d, %s, %s, current_timestamp())"
            self.curs.execute(sql, (processUUID, hostURL, count, URIs, state,))
            self.conn.commit()
        except Exception as e:
            # 에러가 발생하면 쿼리를 롤백한다.
            self.conn.rollback()
            raise e

    def getReq(self, processUUID: str):
        try:
            sql = "select * from IF_DICOMLINK_REQ where process_uuid = %s"
            self.curs.execute(sql, (processUUID,))
            return self.curs.fetchone()
        except Exception as e:
            raise e

    def updateState(self, processUUID: str, newState: str):
        try:
            sql = "update IF_DICOMLINK_REQ set state = %s, update_dt = current_timestamp() where process_uuid = %s"
            self.curs.execute(sql, (newState, processUUID,))
            self.conn.commit()
        except Exception as e:
            # 에러가 발생하면 쿼리를 롤백한다.
            self.conn.rollback()
            raise e
