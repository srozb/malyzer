# -*- coding: utf-8 -*-

from ConfigParser import RawConfigParser
#from logger import Logger

config_file = "malyzer.conf"

p = RawConfigParser()
p.read(config_file)


#main
version = "1.1 beta3"  # why not hardcode it ;-)
debug = p.getboolean("main", "debug")
silent = p.getboolean("main", "silent")
machine_id_filename = p.get("main", "machine_id_filename")
tag = p.get("main", "tag")

#multiprocessing
workers_num = p.getint("multiprocessing", "workers_num")
queue_size = p.getint("multiprocessing", "queue_size")

#debugger
antianti = p.getboolean("debugger", "antianti")

#hooks
hook_modules = p.get("hooks", "modules")

#libmagic
enable_magic = p.getboolean("libmagic", "enabled")
magic_file = p.get("libmagic", "magic_file")
default_ext = p.get("libmagic", "default_extension")
libmagic_buf_limit = p.getint("libmagic", "buf_limit")

#console
show_create_thread = p.getboolean("console", "show_create_thread")
log_level = p.get("console", "log_level")
console_log_format = p.get("console", "log_format")
console_buf_limit = p.getint("console", "buffer_limit")

#logging
log_dir = p.get("logging", "log_dir")
log_hooks_to_file = p.getboolean("logging", "log_hooks_to_file")
enable_filedump = p.getboolean("logging", "enable_filedump")
dump_dir = p.get("logging", "dump_dir")
dump_index_filename = p.get("logging", "dump_index_filename")
sql_log = p.getboolean("logging", "sql_log")
log_db = p.get("logging", "log_db")
make_summary = p.getboolean("logging", "make_summary")
strft_fmt = p.get("logging", "strft_fmt")
ts_fmt = p.get("logging", "ts_fmt")

#l = Logger(__name__)  # this causes cross importing errors logger/config etc.
#l.debug("reading config file: {} done.".format(config_file))