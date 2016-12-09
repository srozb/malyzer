# -*- coding: utf-8 -*-


class Target(str):

    def isPath(self):
        return self.__contains__('/') or self.__contains__('\\')


