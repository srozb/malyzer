# -*- coding: utf-8 -*-

import logging
import config
from datetime import datetime


class Logger():

    def __init__(self, mod_name):
        self.logger = logging.getLogger(mod_name)
        self.logger.setLevel(config.log_level)
        self.formatter = logging.Formatter(config.console_log_format)
        self.handler = logging.StreamHandler()
        self.handler.setFormatter(self.formatter)
        self.logger.addHandler(self.handler)
        self.logfiles = {}

    def _getStrftNow(self):
        return datetime.strftime(datetime.now(), config.strft_fmt)

    def debug(self, buf):
        self.logger.debug(buf)

    def info(self, buf):
        self.logger.info(buf)

    def warn(self, buf):
        self.logger.warn(buf)

    def error(self, buf):
        self.logger.error(buf)

    def critical(self, buf):
        self.logger.critical(buf)

    def conPrint(self, buf, event_time=None):
        if config.silent:
            return
        if not event_time:
            event_time = self._getStrftNow()
        if (len(buf) > config.console_buf_limit):
            buf = buf[:config.console_buf_limit] + '(...)\n'
        print("{} {}".format(event_time, buf))

    def _getFileDescriptor(self, filename):
        if filename in self.logfiles:
            return self.logfiles[filename]
        else:
            desc = open(filename, 'a')
            self.logfiles[filename] = desc
            return desc

    def _flushAll(self):
        for f in self.logfiles:
            f.flush()

    def _generateDumplogFilename(self, pid, function):
        return "{}/{}_{}.txt".format(config.log_dir, pid, function)

    def _writeLog(self, filename, buf):
        f = self._getFileDescriptor(filename)
        f.write(buf)
        f.flush()  # might be a performance issue - to investigate
        #f.close()  # this might break things.

    def fileLog(self, pid, function, buf, event_time=None):
        if not config.log_hooks_to_file:
            return
        if not event_time:
            event_time = self._getStrftNow()
        buf = "{} {}\n".format(event_time, buf)
        filename = self._generateDumplogFilename(pid, function)
        self._writeLog(filename, buf)



