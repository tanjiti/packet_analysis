# -*- coding: utf-8 -*-
import logging
import platform
import socket
import struct
import subprocess

import mills


def getPortNumHostByteOrder(st_network):
    """
    Convert 16-bit positive integers from network to host byte order. On machines where the host byte order is the same as network byte order, this is a no-op; otherwise, it performs a 2-byte swap operation
    :param st_network:
    :return: 20480 - 80
    """
    try:
        st_network = int(st_network)
        return socket.ntohs(st_network)
    except Exception as e:
        logging.error("[NetworkByteOrderPortFalse]: %f %s" % (st_network, repr(e)))


def getPortNumNetworkByteOrder(st_host):
    """
    Convert 16-bit positive integers from host to network byte order. On machines where the host byte order is the same as network byte order, this is a no-op; otherwise, it performs a 2-byte swap operation.
    :param st_host:
    :return: 80-20480
    """
    try:
        st_host = int(st_host)
        return socket.htons(st_host)
    except Exception as e:
        logging.error("[HostByteOrderPortFalse]: %f %s" % (st_host, repr(e)))


def long2ip(i, byteorder='little'):
    """

    :param str:
    :param byteorder:
    :return:
    """
    if byteorder == "little":
        fmt = '>L'
    else:
        fmt = '<L'
    return socket.inet_ntoa(struct.pack(fmt, i))


def ip2long(str, byteorder="little"):
    """

    :param str:
    :param byteord:  big-endian（network）， little-endian （hostwork）
    :return:
    """
    if byteorder == "little":
        fmt = '>L'
    else:
        fmt = '<L'

    return struct.unpack(fmt, socket.inet_aton(str))[0]


def hexstr2ip(hex_str, byteorder="little"):
    """
    little byte order 将低序字节存储在起始地址

    06e6a8c0 -> 192.168.230.6
    Args:
        hex_str:

    Returns:

    """
    if byteorder == "little":
        fmt = "<L"
    else:
        fmt = ">L"

    return socket.inet_ntoa(struct.pack(fmt, int(hex_str, base=16)))


def hexstr2int(hex_str, byteorder="little"):
    """
    3050895900000000 --> 1502171184
    :param hex_str:
    :return:
    """
    if byteorder == 'little':
        hex_str = mills.reversestr(hex_str, st_step=2)
    return int(hex_str, base=16)


def hexstr2datetime(hex_str, byteorder='little'):
    """

    :param hex_str:
    :return:
    """

    return mills.timestamp2datetime(ts=hexstr2int(hex_str, byteorder))


def get_local_ip(interface="en0"):
    """

    Args:
        interface:

    Returns:

    """
    cmd_linux = 'ifconfig %s|awk "/inet /"|cut -d":" -f 2|cut -d" " -f1' % interface
    cmd_darwin = 'ifconfig %s|awk "/inet /"|cut -d":" -f 2|cut -d" " -f2' % interface
    cur_system = platform.system().lower()
    if cur_system.find("linux") != -1:
        cmd = cmd_linux
    else:
        cmd = cmd_darwin
    local_ip = subprocess.Popen([cmd],
                                stdout=subprocess.PIPE,
                                shell=True)
    (IP, errors) = local_ip.communicate()
    local_ip.stdout.close()
    IP = IP.strip()
    return IP


if __name__ == "__main__":
    from optparse import OptionParser
    import logger

    logger.generate_special_logger(level=logging.INFO,
                                   logtype="network",
                                   curdir=mills.path("log/"),
                                   ismultiprocess=False
                                   )
    parser = OptionParser()

    parser.add_option(
        "--portHost", dest='getPortHostByteOrder',
        action="store", type="int",
        help="change network byte order port to host byte order port(20480 - 80)",
        # default=20480
    )
    parser.add_option(
        "--portNetwork", dest='getPortNetworkByteOrder',
        action="store", type="int",
        help="change host byte order port to network byte order port(80-20480)",
        # default=80
    )

    parser.add_option(
        "--ip2long", dest="getIP2long",
        action='store', type='string',
        help="change ip dot-decimal to long(192.168.230.6-115779776 big-endian)",
        # default="192.168.230.6"
    )

    parser.add_option(
        "--long2ip", dest='getlong2IP',
        action='store', type='int',
        help="change long 2 ip dot-decimal(115779776 -192.168.230.6 big-endian) "
    )
    parser.add_option(
        "--byteorder", dest="byteOrder",
        action='store', type='string',
        help='special the byteorder,support little endian(host), big endian (network), default is little',
        default='little'
    )

    parser.add_option(
        "--hexstr2int", dest="hex2int",
        action='store', type='string',
        help='transform hex_str 2 int, example (1500 --> 21 )',

    )

    parser.add_option(
        "--hexstr2ip", dest="hex2ip",
        action='store', type='string',
        help='transform hex_str 2 ip, example(06e6a8c0 --> 192.168.230.6)'
    )

    parser.add_option(
        "--hexstr2datetime", dest="hex2datetime",
        action='store', type='string',
        help='transform hex_str 2 datetime, example(3050895900000000 --> 2017-08-08 13:46:24)'
    )

    parser.add_option(
        "--getLocalIP", dest="getLocalIP",
        action="store", type='string',
        help='get local ip from ifconfig, only support linux and darwin system',

    )
    (options, args) = parser.parse_args()

    if options.getPortHostByteOrder:
        print options.getPortHostByteOrder, getPortNumHostByteOrder(options.getPortHostByteOrder)

    if options.getPortNetworkByteOrder:
        print options.getPortNetworkByteOrder, getPortNumNetworkByteOrder(options.getPortNetworkByteOrder)

    if options.getIP2long:
        print options.getIP2long, ip2long(options.getIP2long, byteorder=options.byteOrder), options.byteOrder

    if options.getlong2IP:
        print options.getlong2IP, long2ip(options.getlong2IP, byteorder=options.byteOrder), options.byteOrder

    if options.hex2int:
        print options.hex2int, hexstr2int(options.hex2int, byteorder=options.byteOrder), options.byteOrder

    if options.hex2ip:
        print options.hex2ip, \
            hexstr2int(options.hex2ip, byteorder=options.byteOrder), \
            hexstr2ip(options.hex2ip, byteorder=options.byteOrder), options.byteOrder

    if options.hex2datetime:
        print options.hex2datetime, \
            hexstr2int(options.hex2datetime, byteorder=options.byteOrder), \
            hexstr2datetime(options.hex2datetime, byteorder=options.byteOrder), options.byteOrder

    if options.getLocalIP:
        print get_local_ip(options.getLocalIP)
