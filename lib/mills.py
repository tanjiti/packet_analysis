# -*- coding: utf-8 -*-
import base64
import datetime
import inspect
import logging
import os
import socket
import struct
import time
from functools import wraps

import requests

def fn_timer(function):
    @wraps(function)
    def function_timer(*args, **kwargs):
        t0 = time.time()
        result = function(*args, **kwargs)
        t1 = time.time()
        logging.info("[FUNCOST]: %s: %s seconds" %
                     (function.func_name, str(t1 - t0))
                     )
        return result

    return function_timer


def classinstance2dict(classinstance):
    """
    class instance object to dict
    :param classinstance:
    :return:
    """
    if not classinstance:
        return
    attributes = inspect.getmembers(classinstance, lambda a: not (inspect.isroutine(a)))
    kvlist = [a for a in attributes if not ((a[0].startswith('__') and a[0].endswith('__')) or a[0].startswith('_'))]

    result = {}
    for k, v in kvlist:
        result[k] = v
    return result


def path(*paths):
    """

    :param paths:
    :return:
    """
    MODULE_PATH = os.path.dirname(os.path.realpath(__file__))
    ROOT_PATH = os.path.join(MODULE_PATH, os.path.pardir)
    return os.path.abspath(os.path.join(ROOT_PATH, *paths))


def getCurrenttimestamp():
    """
    get current timestamp in float format
    Returns:

    """
    return time.time()


def timestamp2datetime(ts, tformat="%Y-%m-%d %H:%M:%S"):
    """
    timestamp 2 datetime
    :param timestamp:
    :return:
    """
    ts = ts
    timestamp = datetime.datetime.fromtimestamp(ts).strftime(tformat)
    return timestamp


def get_cur_date(delta=0, format="%Y%m%d"):
    """
    now 20160918, default delta = 0
    :return:
    """
    date = (datetime.date.today() - datetime.timedelta(days=delta)).strftime(format)
    return date


def get_cur_hour_24():
    """
    the hour of today
    :return:
    """
    current_hour = time.strftime('%H', time.localtime(time.time()))
    return current_hour


def is_base64(s):
    """
    check a str is base64 decode or not
    :param s:
    :return:
    """
    try:
        enc = base64.b64decode(s)
        return enc
    except:
        return None


def str2hex(st, return_str=False):
    """

    :param st:
    :return:
    """

    result = ["%02x" % ord(x) for x in st]

    if return_str:
        result = ''.join(result)

    return result


def str2hex2(data, length=16, sep='.'):
    """

    Args:
        data:
        length:
        sep:

    Returns:

    """
    lines = []
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    for c in xrange(0, len(data), length):
        chars = data[c:c + length]
        hex_str = ' '.join(["%02x" % ord(x) for x in chars])
        printablechars = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
        lines.append("%08x: %-*s |%s|\n" % (c, length * 3, hex_str, printablechars))

    return ''.join(lines)


def rm_dir(dirpath):
    """

    :param dirpath:
    :return:
    """

    for root, dirs, files in os.walk(dirpath, topdown=False):

        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir(dirpath)


def isFileEmpty(filename):
    """
    check a file is empty or not
    :param filename:
    :return:
    """
    if not os.path.exists(filename):
        return True
    if os.stat(filename).st_size == 0:
        return True
    return False


def network2ip(hex_str):
    """
    d8ef391a - 216.239.57.26
    Args:
        hex_str:

    Returns:

    """
    return socket.inet_ntoa(struct.pack('!L', int(hex_str, base=16)))


def ip2long(str):
    """
    216.239.57.26 - 3639556378
    Args:
        str:

    Returns:

    """

    return struct.unpack('!L', socket.inet_aton(str))[0]


def hex2int(hex_str):
    """

    Args:
        hex_str:

    Returns:

    """
    return int(hex_str, base=16)


def binary2int(bin_str):
    """

    Args:
        bin_str:

    Returns:

    """
    return int(bin_str, base=2)


def hex2chr(hex_list):
    return "".join(chr(int(h, base=16)) for h in hex_list)

def request_common(url=None, method=None, headers=None, auth=None,
                   params=None, data=None, timeout=10, json=None,
                   debug=False):
    """

    :param url:
    :param method:
    :param headers:
    :param proxy:
    :param auth:
    :param params:
    :param data:
    :param timeout:
    :param debug:
    :return:
    """

    s = requests.session()

    # setting headers
    if not headers:
        headers = {}

    headers[
        'User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 " \
                        "(KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36"

    s.headers.update(headers)

    try:
        r = s.request(method, url, params=params, data=data, auth=auth, timeout=timeout, json=json)

        if debug:
            content = ">>>>>>>>> %s %s detail >>>>>>>>\n" % (method, r.url)
            content = content + ">>>>request header: \n"
            content = content + repr(r.request.headers) + "\n"

            content = content + ">>>>response header: \n"
            content = content + repr(r.headers) + "\n"

            content = content + ">>>>response code: \n"
            content = content + repr(r.status_code) + "\n"

            content = content + ">>>>response content: \n"
            content = content + repr(r.content) + "\n"
            content = content + ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"
            logging.debug(content)
            print content

    except Exception as e:
        content = "%s %s failed  %r" % (method, url, e)
        if debug:
            logging.debug(content)
            print content
        return
        # return None
    return r


def list2str(l, pattern="%s,%s"):
    """
    convert list obj to string: [1,2,3,4] ---> 1,2,3,4
    :param l:
    :return:
    """
    if not (isinstance(l, list) or isinstance(l, set) or isinstance(l, tuple)):
        content = "%s is not a list" % repr(l)
        print content
        return

    l_str = ""
    for i in l:
        len_ob = pattern.count("%s")
        if len_ob == 2:
            l_str = pattern % (l_str, i)
        elif len_ob == 3:
            l_str = pattern % (l_str, i, i)

    l_str = l_str[1:]
    return l_str


if __name__ == "__main__":
    from optparse import OptionParser
    import lib.logger as logger

    logger.generate_special_logger(level=logging.INFO,
                                   logtype="mills",
                                   curdir=path("./log"))
    parser = OptionParser()

    parser.add_option(
        "--ts2datetime", dest="ts",
        action='store', type='float',
        help="special the fake data filename",
        default=getCurrenttimestamp()
    )

    (options, args) = parser.parse_args()
    print timestamp2datetime(options.ts)


