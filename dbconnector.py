# -*- coding: utf-8 -*-

import config
import dataset
from storagepool import sp
from logger import Logger
from helper import mkdir

l = Logger(__name__)


class DBConnector():

    def __init__(self):
        self.f = open(
            config.log_dir + '/log.sql', 'w') if (config.sql_log
                and config.log_db) else None
        ""
        self.db_session_id = None
        self.db = self._initDb() if config.log_db else None

    def _log(self, buf):  # broken.
        if self.f:
            self.f.write('{}\n'.format(buf))
            self.f.flush()

    def _initDb(self):
        db = dataset.connect(config.log_db)
        l.info('{} db backend connected.'.format(db.engine.name))
        return db

    def _setDbSessionId(self, sid):
        sp.setDbSessionId(sid)

    def _getDbSessionId(self):
        return sp.getDbSessionId()

    def _getLastRowId(self):
        return self.cur.lastrowid

    def ProcessStartup(self, target=""):  # db connection stays open
        if not self.db:
            return
        session_table = self.db['sessions']
        data = dict(machine_id=sp.machine_id,
            analysis_id=sp.analysis_id,
            tag=config.tag,  # test if properly escaped
            version=config.version,
            target=target)
        session_id = session_table.insert(data)
        self._setDbSessionId(session_id)
        l.debug('INSERTING: {}'.format(data))  # use pprint

    def ProcessHook(self, ev):
        if not self.db:
            return
        hook_table = self.db['hooks']  # BUG: sqlite3 driver tries to create...
        data = dict(pid=ev.pid,
            tid=ev.tid,
            function=ev.function,
            payload=buffer(ev.payload),
            exact_param=ev.exact_param,
            session_id=self._getDbSessionId(),
            category=ev.category)
        hook_table.insert(data)  # BUG: sqlite3 driver tries to create existing
        l.debug('ÍNSERTING: {}'.format(data))


mkdir(config.log_dir)  # todo: remove this function.
