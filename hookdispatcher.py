# -*- coding: utf-8 -*-

from logger import Logger
from helper import hexaddr
from clock import Clock
from eventqueue import eq
from collections import namedtuple

l = Logger(__name__)
c = Clock()
ev = namedtuple("Event", "event_time pid tid function hex_addr payload \
                category exact_param")


class HookDispatcher():

    def __init__(self):
        "Decide what to do with given hook"

    def _retrieveBasicInfo(self, event):
        pid = event.get_pid()
        tid = event.get_tid()
        bits = event.get_process().get_bits()
        address = event.get_thread().get_pc()
        hex_addr = '0x{}'.format(hexaddr(address, bits))
        return pid, tid, bits, address, hex_addr

    def _sendToQueue(self, pid, tid, function, hex_addr, payload, category=None,
            exact_param=None):
        event_time = c.getStrftNow()
        hook_event = ev(event_time, pid, tid, function, hex_addr, payload,
            category, exact_param)
        eq.addHookEvent(hook_event)

    def dispatch(self, event, function, buf, category=None, exact_param=None):
        pid, tid, bits, address, hex_addr = self._retrieveBasicInfo(event)
        self._sendToQueue(pid, tid, function, hex_addr, buf, category,
            exact_param)
