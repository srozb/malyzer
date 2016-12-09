# -*- coding: utf-8 -*-

import config
from sys import argv
from winappdbg import Debug
from ev_tracer import TracingEventHandler
from art import banner
from uuid import uuid4
from logger import Logger
from helper import *
from storagepool import sp
from reporter import Reporter
from target import Target
from threading import Thread
from queueprocessor import QueueProcessor
from dbconnector import DBConnector

EH = TracingEventHandler()
r = Reporter()
db = DBConnector()

machine_id = str()


def keyboardInt():
    l.warn("Keyboard interrupt. Cleaning up.")


def _resolvePid(pid):
    proc_name = debug.system.get_process(pid).get_filename()
    return proc_name.split('\\')[-1]


def attachToFilename(filename):
    try:
        debug.system.scan_processes()
        for (process, name) in debug.system.find_processes_by_filename(
                filename):
            pid = process.get_pid()
            sp.addTarget(pid, name)
            l.warn("Attaching to: {} {}".format(process.get_pid(), name))
            debug.attach(pid)
        debug.loop()
    except KeyboardInterrupt:
        keyboardInt()
    finally:
        debug.stop()


def attachToPid(pid):
    try:
        proc_name = _resolvePid(pid)
        l.warn("Attaching to {} {}".format(pid, proc_name))
        sp.addTarget(pid, proc_name)
        debug.attach(pid)
        debug.loop()
    except KeyboardInterrupt:
        keyboardInt()
    finally:
        debug.stop()


def runAndAttach(target):
    try:
        P = debug.execv(target, bFollow=True)
        pid = P.get_pid()
        proc_name = _resolvePid(pid)
        sp.addTarget(pid, proc_name)
        debug.loop()
    except KeyboardInterrupt:
        keyboardInt()
    finally:
        debug.stop()


def askForTarget():
    return raw_input('PID/process name/executable to analyse: ')


def _initDirs():
    mkdir(config.log_dir)
    if config.enable_filedump:
        dump_path = config.log_dir + '/' + config.dump_dir
        mkdir(dump_path)


def _generateUUID():
    return str(uuid4())


def _readMachineId(filename):
    try:
        f = open(filename, 'r')
        buf = f.readline()[:36]
        f.close()
        if len(buf) == 36:
            return buf
    except:
        pass


def _writeMachineId(filename, machine_id):
    l.debug('saving new machine id to file: {}'.format(filename))
    with open(filename, 'w') as f:
        f.write(machine_id)


def _setMachineId():
    machine_id = _readMachineId(config.machine_id_filename)
    if not machine_id:
        l.debug("couldn't read machine id from file: {}".format(
            config.machine_id_filename))
        machine_id = _generateUUID()
        _writeMachineId(config.machine_id_filename, machine_id)
    l.debug('machine id = {}'.format(machine_id))
    sp.setMachineId(machine_id)
    return machine_id


def _setAnalysisId():
    analysis_id = _generateUUID()
    sp.setAnalysisId(analysis_id)


def _spawnThreads():
    for i in range(config.workers_num):
        qp = QueueProcessor()
        t = Thread(target=qp.Work)
        t.setDaemon(True)
        t.start()

print(banner())
l = Logger("main")


if __name__ == "__main__":  # TODO: log.error when target couldn't be found
    _initDirs()
    _spawnThreads()
    machine_id = _setMachineId()
    analysis_id = _setAnalysisId()
    debug = Debug(EH, bHostileCode=config.antianti)  # ANTIANTI = EXPERIMENTAL
    target = Target(argv[1] if len(argv) == 2 else askForTarget())
    db.ProcessStartup(target)
    l.warn('Malyzer analysis started.')
    if (target.isdigit()):
        attachToPid(int(target))
    elif (target.isPath()):
        runAndAttach(target.split(' '))  # make cmd and args apart
    else:
        attachToFilename(target)
    if config.make_summary:
        r.printReport(machine_id)
    l.conPrint("Thank you for using malyzer ;-)")

