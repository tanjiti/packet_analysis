# -*- coding: utf-8 -*-
import datetime
import inspect
import logging
import os
import socket
import time
from collections import OrderedDict

import dpkt
from dpkt.compat import compat_ord

import lib.logger as logger

TCP_FLAG_DICT = OrderedDict(
    [("128", "CWR"), ("64", "ECE"), ("32", "URG"), ("16", "ACK"), ("8", "PSH"), ("4", "RST"), ("2", "SYN"),
     ("1", "FIN")])

ICMP_TYPE = {
    3: {  # ICMP TYPE
        3: "host:port unreachable",  # ICMP CODE
        2: "host:protocol unavaiable",
        0: "gateway:network unreachable",
        1: "gateway:host unreachable",

    },
    15: {
        0: "host: send a message request"
    },
    16: {
        0: "gateway: send a message response"
    },
    8: {
        0: "gateway: send a response"
    },
    13: {
        0: "host: send a timestamp request"
    },
    14: {
        0: "gateway: send a timestamp response"
    },
    0: {
        0: "host/gateway: send response "
    }

}


class PCAPOb(object):
    def __init__(self,
                 timestamp="",
                 timestamp_num="",
                 package_type="",

                 src_ip="",
                 src_port="",
                 src_mac="",

                 dst_ip="",
                 dst_port="",
                 dst_mac="",

                 len_tcpudp_data=0,
                 tcpudp_data="",
                 tcpudp_data_binary="",

                 tcp_seq=None,
                 tcp_ack=None,
                 tcp_flags=None,
                 tcp_flags_list=None,
                 tcp_win=None,
                 icmp_type=None,
                 icmp_code=None,
                 ttl=None,
                 ):
        self.timestamp = timestamp
        self.timestamp_num = timestamp_num
        self.package_type = package_type

        self.src_ip = src_ip
        self.src_port = src_port
        self.src_mac = src_mac

        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.dst_mac = dst_mac

        self.tcpudp_data = tcpudp_data
        self.tcpudp_data_binary = tcpudp_data_binary
        self.len_tcpudp_data = len_tcpudp_data

        self.tcp_seq = tcp_seq
        self.tcp_ack = tcp_ack
        self.tcp_flags = tcp_flags
        self.tcp_flags_list = tcp_flags_list
        self.tcp_win = tcp_win

        self.icmp_type = icmp_type
        self.icmp_code = icmp_code
        self.icmp_message = ICMP_TYPE.get(icmp_type, {}).get(icmp_code)
        self.ttl = ttl

    def toDict(self):
        attributes = inspect.getmembers(self, lambda a: not (inspect.isroutine(a)))
        kvlist = [a for a in attributes if not (a[0].startswith('__') and a[0].endswith('__'))]
        result = {}
        for k, v in kvlist:
            result[k] = v
        return result

    def format_package_output(self):
        """
        format pcap package output
        :param result:
        :return:
        """
        if self.package_type == "TCP":

            content_format = "[{package_type}]\t[{timestamp_num}\t{timestamp}]\t{src_ip}:{src_port}({src_mac}) ----->" \
                             "{dst_ip}:{dst_port}({dst_mac})\t" \
                             "SEQ={tcp_seq}\tACK={tcp_ack}\tFLAGS={tcp_flags_list}\tWIN={tcp_win}\t" \
                             "DATA={tcpudp_data}\t" \
                             "ttl={ttl}\tDATA_BINARY={tcpudp_data_binary}\tLEN={len_tcpudp_data}"
            content = content_format.format(
                package_type=self.package_type,
                timestamp_num=self.timestamp_num,
                timestamp=self.timestamp,
                src_ip=self.src_ip,
                src_port=self.src_port,
                src_mac=self.src_mac,
                dst_ip=self.dst_ip,
                dst_port=self.dst_port,
                dst_mac=self.dst_mac,
                tcp_seq=self.tcp_seq,
                tcp_ack=self.tcp_ack,
                tcp_flags_list=self.tcp_flags_list,
                tcp_win=self.tcp_win,
                tcpudp_data=self.tcpudp_data,
                tcpudp_data_binary=self.tcpudp_data_binary,
                len_tcpudp_data=self.len_tcpudp_data,
                ttl=self.ttl
            )
        elif self.package_type == "UDP":
            content_format = "[{package_type}]\t[{timestamp_num}\t{timestamp}]\t{src_ip}:{src_port}({src_mac}) ----->" \
                             "{dst_ip}:{dst_port}({dst_mac})\t" \
                             "ttl={ttl}\tDATA_BINARY={tcpudp_data_binary}\tLEN={len_tcpudp_data}"
            content = content_format.format(
                package_type=self.package_type,
                timestamp_num=self.timestamp_num,
                timestamp=self.timestamp,
                src_ip=self.src_ip,
                src_port=self.src_port,
                src_mac=self.src_mac,
                dst_ip=self.dst_ip,
                dst_port=self.dst_port,
                dst_mac=self.dst_mac,
                tcpudp_data_binary=self.tcpudp_data_binary,
                len_tcpudp_data=self.len_tcpudp_data,
                ttl=self.ttl
            )
        elif self.package_type.startswith("ICMP"):
            content_format = "[{package_type}]\t[{timestamp_num}\t{timestamp}]\t{src_ip}:{src_port}({src_mac}) ----->" \
                             "{dst_ip}:{dst_port}({dst_mac})\t{icmp_type}:{icmp_code}[{icmp_message}]\t" \
                             "ttl={ttl}\tDATA_BINARY={tcpudp_data_binary}\tLEN={len_tcpudp_data}"
            content = content_format.format(
                package_type=self.package_type,
                timestamp_num=self.timestamp_num,
                timestamp=self.timestamp,
                src_ip=self.src_ip,
                src_port=self.src_port,
                src_mac=self.src_mac,
                dst_ip=self.dst_ip,
                dst_port=self.dst_port,
                dst_mac=self.dst_mac,
                tcpudp_data_binary=self.tcpudp_data_binary,
                len_tcpudp_data=self.len_tcpudp_data,
                icmp_type=self.icmp_type,
                icmp_code=self.icmp_code,
                icmp_message=self.icmp_message,
                ttl=self.ttl
            )
        return content


# https://dpkt.readthedocs.io/en/latest/
def str2hex(st):
    """

    :param st:
    :return:
    """
    result = ["%02x" % ord(x) for x in st]

    result = ' '.join(result)

    return result


def convert(dec, flags=None):
    """
    convert tcp flags number to flags String array
    :param dec:
    :param flags:
    :return:
    """
    final = []
    if flags is None:
        flags = TCP_FLAG_DICT
    for i in flags.keys():
        if (dec >= int(i)):
            dec = dec - int(i)
            final.append(flags[i])
    return final


def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


class PCAPParse(object):
    def __init__(self, pcap):
        self.f = None
        self.pcap = None
        if isinstance(pcap, dpkt.pcap.Reader):
            pass
        elif os.path.exists(pcap):
            f = open(pcap)
            try:
                pcap = dpkt.pcap.Reader(f)
                self.pcap = pcap
            except Exception as e:
                logging.error("dpkt.pcap.Reader failed: %s" % repr(e))
                return
            self.f = f

    def __del__(self):
        if self.f:
            self.f.close()

    def analysis_pcap(self):
        """
        analysis pcap
        :param pcap:dpkt.pcap.Reader Libpcap file format or a file
        :param asset_ip: array
        :param asset_port: array
        :return:
        """
        if self.pcap is None:
            return
        for ts, buf in self.pcap:

            # timestamp
            ts_num = ts - time.timezone
            ts = datetime.datetime.fromtimestamp(ts_num + time.timezone).strftime("%Y-%m-%d %H:%M:%S")

            if buf:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)

                except dpkt.dpkt.NeedData as e:
                    logging.error("%s : %s" % (repr(buf), repr(e)))
                    continue
            else:
                continue

            # mac addr
            src_mac = mac_addr(eth.src)
            dst_mac = mac_addr(eth.dst)

            # ip data package
            ip = eth.data

            if isinstance(ip, dpkt.ip.IP):
                ip_type = "ipv4"
            elif isinstance(ip, dpkt.ip6.IP6):
                ip_type = "ipv6"
            else:
                ip_type = eth.data.__class__.__name__
                loop_ip = dpkt.loopback.Loopback(buf).data

                if isinstance(loop_ip, dpkt.ip.IP):
                    ip_type = "ipv4"
                    ip = loop_ip
                elif isinstance(loop_ip, dpkt.ip6.IP6):
                    ip_type = "ipv6"
                else:
                    logging.error('No Valid IP Packet(not v4 or v6): %s %r '
                                  'src_mac:%s dst_mac:%s\n' % (ip_type, ip
                                                               , src_mac,
                                                               dst_mac))
                    continue

            if ip_type == "ipv4":
                # src ip and dest ip
                try:
                    src_ip = socket.inet_ntoa(ip.src)
                except socket.error as e:
                    logging.error("ip.src %s parse failed: %s" % (ip.src, repr(e)))
                    continue
                try:
                    dst_ip = socket.inet_ntoa(ip.dst)
                except socket.error as e:
                    logging.error("ip.dst %s parse failed: %s" % (ip.dst, repr(e)))
                    continue
            else:
                src_ip = ip.src
                dst_ip = ip.dst

            # Internet Protocol
            data = ip.data
            ttl = ip.ttl

            if isinstance(data, dpkt.tcp.TCP):

                sport = data.sport
                dport = data.dport
                tcp_win = data.win

                tcpudp_data = data.data
                len_tcpudp_data = len(tcpudp_data)
                tcpudp_data_binary = str2hex(tcpudp_data)
                seq = data.seq
                ack = data.ack
                flags = data.flags
                flags_list = convert(flags)

                data_type = "TCP"
                result = PCAPOb(timestamp=ts,
                                timestamp_num=ts_num,
                                package_type=data_type,
                                src_ip=src_ip,
                                src_port=sport,
                                src_mac=src_mac,
                                dst_ip=dst_ip,
                                dst_port=dport,
                                dst_mac=dst_mac,
                                len_tcpudp_data=len_tcpudp_data,
                                tcpudp_data=tcpudp_data,
                                tcpudp_data_binary=tcpudp_data_binary,
                                tcp_seq=seq,
                                tcp_ack=ack,
                                tcp_flags=flags,
                                tcp_flags_list=flags_list,
                                tcp_win=tcp_win,
                                ttl=ttl)

                yield result
            elif isinstance(data, dpkt.udp.UDP):
                sport = data.sport
                dport = data.dport
                tcpudp_data = data.data
                len_tcpudp_data = len(tcpudp_data)
                # change data2hex
                tcpudp_data_binary = str2hex(tcpudp_data)
                data_type = "UDP"
                result = PCAPOb(timestamp=ts,
                                timestamp_num=ts_num,
                                package_type=data_type,
                                src_ip=src_ip,
                                src_port=sport,
                                src_mac=src_mac,
                                dst_ip=dst_ip,
                                dst_port=dport,
                                dst_mac=dst_mac,
                                len_tcpudp_data=len_tcpudp_data,
                                tcpudp_data=tcpudp_data,
                                tcpudp_data_binary=tcpudp_data_binary,
                                ttl=ttl
                                )
                yield result
            elif isinstance(data, dpkt.icmp.ICMP):
                icmp_type = data.type
                icmp_code = data.code

                icmp_data = data.data

                if isinstance(icmp_data.data, basestring):
                    continue

                ttl = icmp_data.data.ttl

                icmp_data_instance = repr(type(icmp_data))
                class_pos = icmp_data_instance.find("dpkt.icmp")

                if class_pos != -1:
                    data_type = "ICMP_%s" % icmp_data_instance[class_pos + 10:-2]

                else:

                    data_type = "ICMP_OTHER"

                if isinstance(icmp_data, dpkt.icmp.ICMP.Unreach):

                    data = icmp_data.data.data
                    sport = data.sport
                    dport = data.dport

                    tcpudp_data = data.data
                    len_tcpudp_data = len(tcpudp_data)
                    tcpudp_data_binary = str2hex(tcpudp_data)
                    result = PCAPOb(timestamp=ts,
                                    timestamp_num=ts_num,
                                    package_type=data_type,
                                    src_ip=src_ip,
                                    src_port=sport,
                                    src_mac=src_mac,
                                    dst_ip=dst_ip,
                                    dst_port=dport,
                                    dst_mac=dst_mac,
                                    len_tcpudp_data=len_tcpudp_data,
                                    tcpudp_data_binary=tcpudp_data_binary,
                                    tcpudp_data=tcpudp_data,
                                    icmp_code=icmp_code,
                                    icmp_type=icmp_type,
                                    ttl=ttl
                                    )
                else:
                    tcpudp_data_binary = repr(icmp_data)
                    len_tcpudp_data = len(tcpudp_data)
                    result = PCAPOb(timestamp=ts,
                                    timestamp_num=ts_num,
                                    package_type=data_type,
                                    icmp_code=icmp_code,
                                    icmp_type=icmp_type,
                                    tcpudp_data_binary=tcpudp_data_binary,
                                    len_tcpudp_data=len_tcpudp_data)

                yield result

            else:
                logging.info(
                    "[BAD_DATA_TYPE]%s %s(%s) ----> %s(%s) %s %s" % (
                        ts, src_ip, src_mac, dst_ip, dst_mac, type(data), repr(data)))
                continue

    def search_pcap(self, asset_ip=None, asset_port=None):
        """
        search pcap
        :param asset_ip:
        :param asset_port:
        :return:
        """
        for item in self.analysis_pcap():
            src_ip = item.src_ip
            dst_ip = item.dst_ip

            src_port = item.src_port
            dst_port = item.dst_port

            if (asset_ip is None) or (src_ip in asset_ip or dst_ip in asset_ip):

                if (asset_port is None) or (src_port in asset_port or dst_port in asset_port):
                    yield item.format_package_output()

    def output_pcap(self, asset_ip=None, asset_port=None):
        """

        :param pcapfile:
        :param asset_ip:
        :param asset_port:
        :return:
        """

        for l in self.search_pcap(asset_port=asset_port, asset_ip=asset_ip):
            print l


if __name__ == '__main__':

    import lib.mills as mills

    logger.generate_special_logger(level=logging.INFO,
                                   logtype="pcapanalyis",
                                   curdir=mills.path("log")
                                   ,
                                   ismultiprocess=False)
    from optparse import OptionParser

    pcap_path = mills.path("data/pcap_private/redisop.pcap")
    assetip = None
    assetport = None

    parser = OptionParser()

    parser.add_option(
        "--pcapfile", dest="pcapfile",
        action='store', type='string',
        help="special the pcap file path",
        default=pcap_path
    )

    parser.add_option(
        "--assetip", dest="assetip",
        action='store', type='string',
        help="special the assetip for search, e.x. 10.0.0.4,10.0.0.5",
        default=assetip
    )

    parser.add_option(
        "--assetport", dest="assetport",
        action='store', type='string',
        help="special the asset port for search, e.x. 80,443 ",
        default=assetport
    )

    (options, args) = parser.parse_args()

    ppo = PCAPParse(options.pcapfile)

    if options.assetip:
        asset_ip = options.assetip.strip().split(",")
        asset_ip = [i.strip() for i in asset_ip]
    else:
        asset_ip = None

    if options.assetport:
        asset_port = options.assetport.strip().split(",")
        asset_port = [int(i.strip()) for i in asset_port]
    else:
        asset_port = None
    ppo.output_pcap(asset_ip=asset_ip, asset_port=asset_port)
