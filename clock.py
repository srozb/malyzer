# -*- coding: utf-8 -*-

from datetime import datetime
import config


class Clock():
    def __init__(self):
        ""

    def getNow(self):
        return datetime.now()

    def getStrftNow(self):
        now = self.getNow()
        return datetime.strftime(now, config.strft_fmt)

    def getTsNow(self):
        now = self.getNow()
        return datetime.strftime(now, config.ts_fmt)