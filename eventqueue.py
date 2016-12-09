# -*- coding: utf-8 -*-

import config
from Queue import Queue
from logger import Logger

l = Logger(__name__)


class EventQueue(Queue):

    def addHookEvent(self, buf):
        l.debug("adding to queue: {}".format(buf))
        self.put(buf)


eq = EventQueue(maxsize=config.queue_size)