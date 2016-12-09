# -*- coding: utf-8 -*-

import config
from clock import Clock
from storagepool import sp
from filetype import determineFromBuffer
from hashlib import md5


c = Clock()
dump_path = config.log_dir + '/' + config.dump_dir


class FileDumper():

    def __init__(self):
        self.dumplog = None

    def _openDescriptor(self):
        if not self.dumplog:
            self.dumplog = open(dump_path + '/' + config.dump_index_filename,
                'a')

    def _dumplog_write(self, buf):
        ts = c.getStrftNow()
        self.dumplog.write("{}: {}".format(ts, buf))
        self.dumplog.flush()

    def _logDuplicateDump(self, digest):
        self._dumplog_write('skipped duplicate: {}\n'.format(digest))

    def _logDump(self, digest, filename, bufsize):
        self._dumplog_write('dumped: {} ({} bytes)\n'.format(filename, bufsize))

    def _dumpFile(self, filename, buf, digest):
        with open(dump_path + '/' + filename, 'w') as logfile:
            logfile.write(buf)
            logfile.flush()
        sp.addDumpedFile(digest, filename, len(buf))

    def dump(self, funcname, buf):
        if not config.enable_filedump:
            return None, None, None
        self._openDescriptor()
        ts = c.getTsNow()
        digest = md5(buf).hexdigest()
        if sp.digestWasProcessed(digest):
            "Duplicate file - skipping"
            self._logDuplicateDump(digest)
            return None, digest, "duplicate"
        else:
            filetype, fileext = determineFromBuffer(buf)
            filename = 'dump_{}_{}_{}{}'.format(funcname, ts, digest, fileext)
            self._dumpFile(filename, buf, digest)
            self._logDump(filename, digest, len(buf))
            return filename, digest, filetype
