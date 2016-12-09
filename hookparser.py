# -*- coding: utf-8 -*-

import config
import winconst
from logger import Logger


class HookParser():

    def __init__(self):
        self.apihooks = {}
        self.configured_hooks = config.hook_modules.split(' ')

    def enableOnlyConfigured(self):
        for h in self.configured_hooks:
            if h in winconst.hooks:
                self.apihooks[h] = winconst.hooks[h]
                l.debug("Adding {} hook".format(h))
            else:
                l.warn("Don't know how to hook following module: {}".format(h))
        l.info("{} modules defined and enabled.".format(len(self.apihooks)))

    def get_configured_hooks(self):
        self.enableOnlyConfigured()
        return self.apihooks

l = Logger(__name__)