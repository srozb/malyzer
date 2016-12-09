# -*- coding: utf-8 -*-

class StoragePool():

    def __init__(self):
        "Store and manipulate program data"  # TODO: use namedtuple
        self.machine_id = str()
        self.analysis_id = str()
        self.targets = {}
        self.dumped_files = {}
        self.hooked_funcs = {}
        self.threads_started = []
        self.modules_loaded = []
        self.db_session_id = None

    def setMachineId(self, machine_id):
        self.machine_id = machine_id

    def setAnalysisId(self, analysis_id):
        self.analysis_id = analysis_id

    def setDbSessionId(self, db_session_id):
        self.db_session_id = db_session_id

    def getDbSessionId(self):
        return self.db_session_id

    def addDumpedFile(self, digest, filename, buflen):
        self.dumped_files[digest] = (filename, buflen)

    def addHookedFunc(self, func_name, pid, tid):
        if pid not in self.hooked_funcs:
            self.hooked_funcs[pid] = {}
        if tid not in self.hooked_funcs[pid]:
            self.hooked_funcs[pid][tid] = {}
        if func_name not in self.hooked_funcs[pid][tid]:
            self.hooked_funcs[pid][tid][func_name] = 1
        else:
            self.hooked_funcs[pid][tid][func_name] += 1

    def addTarget(self, pid, proc_name):
        self.targets[pid] = proc_name

    def addThread(self, tid):
        if tid not in self.threads_started:
            self.threads_started.append(tid)

    def addModule(self, mod_name):
        if mod_name not in self.modules_loaded:
            self.modules_loaded.append(mod_name)

    def digestWasProcessed(self, digest):
        return digest in self.dumped_files

    def getThreadsNum(self):
        return len(self.threads_started)

    def getTargets(self):
        return self.targets

    def getModulesLoaded(self):
        return self.modules_loaded

    def getHookedFuncs(self):
        return self.hooked_funcs

    def getDumpedFiles(self):
        return self.dumped_files

sp = StoragePool()
