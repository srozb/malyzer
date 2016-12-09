# -*- coding: utf-8 -*-

from logger import Logger
from eventqueue import eq
from storagepool import sp
from dbconnector import DBConnector

l = Logger(__name__)


class QueueProcessor():

    def __init__(self):
        l.debug("Worker spawned")
        self.db = DBConnector()

    def _conPrint(self, ev):
        buf = "[{}] {}({}:{}): {}".format(ev.hex_addr, ev.function, ev.pid,
            ev.tid, ev.payload)
        l.conPrint(buf, ev.event_time)

    def _fileLog(self, ev):
        l.fileLog(ev.pid, ev.function, ev.payload, ev.event_time)

    def Work(self):
        while True:
            ev = eq.get()
            self._conPrint(ev)
            self._fileLog(ev)
            self.db.ProcessHook(ev)
            sp.addHookedFunc(ev.function, ev.pid, ev.tid)  # send the whole ev
            eq.task_done()
