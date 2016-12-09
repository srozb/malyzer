# -*- coding: utf-8 -*-

from mimetypes import guess_extension
import config
from logger import Logger

type_override = {
            'application/octet-stream': '.dmp',
            'text/plain': '.txt',
           }

l = Logger(__name__)


def _importMagic():
    if config.enable_magic:
        try:
            import magic
            return magic.Magic(magic_file=config.magic_file, mime=True)
            l.debug("libmagic enabled.")
        except:
            l.debug("libmagic cannot be imported")
    return None


def _dyreInjectConfig(buf):  # return buf == rpcgroup
    if buf[:10] == "<rpcgroup>":
        return True
    return False


def _dyreRedirectConfig(buf):
    if buf[:12] == "<serverlist>":
        return True
    return False


def _determineExtension(determined_type):
    extension = config.default_ext
    if determined_type in type_override:
        return type_override[determined_type]
    try:
        extension = guess_extension(determined_type)
    except:
        pass
    return extension


def determineFromBuffer(buf):
    if _dyreInjectConfig(buf):  # todo: config.inspectdyre enable/disable
        l.warn("DYRE INJECT CONFIG!!!")
        return "malware/DyreInjectConfiguration", ".conf"
    elif _dyreRedirectConfig(buf):
        l.warn("DYRE REDIRECT CONFIG!!!")
        return "malware/DyreRedirectConfig", ".conf"
    if (m):
        determined_type = m.from_buffer(buf[:config.libmagic_buf_limit])
        extension = _determineExtension(determined_type)
        if not extension:
            return "Unknown", config.default_ext
        return determined_type, extension
    else:
        return "Unknown", config.default_ext

m = _importMagic()