# -*- coding: utf-8 -*-

import config
from storagepool import sp
from tabulate import tabulate

class Reporter():

    def __init__(self):
        "Very curious class"

    def mkTargetsReport(self):
        d = []
        targets = sp.getTargets()
        for counter, t in enumerate(targets):
            counter += 1
            d.append([counter, t, targets[t]])
        return tabulate(d, headers=['#', 'PID', 'Process filename'])

    def mkLoadedModulesReport(self):
        d = []
        modules_loaded = sp.getModulesLoaded()
        for counter, item in enumerate(modules_loaded):
            counter += 1
            d.append([counter, item])
        return tabulate(d, headers=['#', 'Module name'])

    def mkPTHReport(self):
        d = []
        hooked_funcs = sp.getHookedFuncs()
        for p in hooked_funcs:
            for t in hooked_funcs[p]:
                for f in hooked_funcs[p][t]:
                    d.append([p, t, f, hooked_funcs[p][t][f]])
        d = sorted(d, key=lambda tup: tup[3], reverse=True)
        for i in range(len(d)):
            d[i] = [1 + i] + d[i]
        return tabulate(d, headers=['#', 'PID', 'TID', 'Function', 'Counter'])

    def mkDumpedFilesReport(self):
        d = []
        dumped_files = sp.getDumpedFiles()
        for counter, k in enumerate(dumped_files):
            counter += 1
            d.append([counter, dumped_files[k][0], dumped_files[k][1]])
        return tabulate(d, headers=['#', 'Filename', 'Size'])

    def printReport(self, machine_id):
        buf = "*** Analysis summary [Machine ID: {}]:\n\n".format(machine_id)
        buf += ""
        buf += "1. Processes malyzed:\n\n"
        buf += self.mkTargetsReport() + "\n\n"
        buf += "Total {} threads has been spawned during the analysis.\n\n".format(
            sp.getThreadsNum())
        buf += "2. Loaded modules\n\n"
        buf += self.mkLoadedModulesReport() + "\n\n"
        buf += "3. Executed hooks\n\n"
        buf += self.mkPTHReport() + "\n\n"
        buf += "4. Dumped files:\n\n"
        buf += self.mkDumpedFilesReport() + "\n"
        report = open(config.log_dir + '/' + 'malyzer-summary.txt', 'w')  # to reporter class
        report.write(buf)
        print("")
        print(buf)
