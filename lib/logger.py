# -*- coding: utf-8 -*-
import logging
import logging.handlers
import os


def init_log(log_path, level=logging.INFO, when="D", backup=7,
             format="%(levelname)s: %(asctime)s: %(filename)s:%(lineno)d * %(thread)d %(message)s",
             datefmt="%m-%d %H:%M:%S", ismultiprocess=True):
    """
    init_log - initialize log module

    Args:
      log_path      - Log file path prefix.
                      Log data will go to two files: log_path.log and log_path.log.wf
                      Any non-exist parent directories will be created automatically
      level         - msg above the level will be displayed
                      DEBUG < INFO < WARNING < ERROR < CRITICAL
                      the default value is logging.INFO
      when          - how to split the log file by time interval
                      'S' : Seconds
                      'M' : Minutes
                      'H' : Hours
                      'D' : Days
                      'W' : Week day
                      default value: 'D'
      format        - format of the log
                      default format:
                      %(levelname)s: %(asctime)s: %(filename)s:%(lineno)d * %(thread)d %(message)s
                      INFO: 12-09 18:02:42: log.py:40 * 139814749787872 HELLO WORLD
      backup        - how many backup file to keep
                      default value: 7

    Raises:
        OSError: fail to create log directories
        IOError: fail to open log file
    """

    formatter = logging.Formatter(format, datefmt)
    logger = logging.getLogger()
    logger.setLevel(level)
    dir = os.path.dirname(log_path)
    if not os.path.isdir(dir):
        os.makedirs(dir)
    if not ismultiprocess:

        handler = logging.handlers.TimedRotatingFileHandler(log_path + ".log",
                                                            when=when,
                                                            backupCount=backup)
        handler.setLevel(level)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        handler = logging.handlers.TimedRotatingFileHandler(log_path + ".log.wf",
                                                            when=when,
                                                            backupCount=backup)
        handler.setLevel(logging.WARNING)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    else:

        # 多进程写日志，用WatchedFileHandler，配合crontab，完成日志切割
        handler = logging.handlers.WatchedFileHandler(filename=log_path + ".log")
        handler.setLevel(level)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        # 错误日志
        handler = logging.handlers.WatchedFileHandler(filename=log_path + ".log.wf")
        handler.setLevel(logging.WARNING)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


# "log_level": "ERROR",  # DEBUG < INFO < WARNING < ERROR < CRITICAL
def generate_special_logger(level=logging.DEBUG, logtype="nmap", curdir="./log", ismultiprocess=False):
    """
    generate_special_logger
    :param level:
    :param logtype:
    :return:
    """

    log_path = os.path.join(curdir, logtype)

    sp_logger = init_log(log_path=log_path, level=level, ismultiprocess=ismultiprocess)
    return sp_logger
