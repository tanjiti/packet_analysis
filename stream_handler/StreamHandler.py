# -*- coding: utf-8 -*-
import sys

reload(sys)
sys.setdefaultencoding('utf8')
import codecs
import json
import logging
import nids
import os
import socket
import struct
import traceback
from collections import OrderedDict

import lib.mills as mills
import lib.networktools as networktools
from lib.ip.geolookup import ip_lookup
from lib.outputob import SQLiteOper
from lib.port.portlookup import PortServiceMap
from protocol_parse.dns import DNSProtocol
from protocol_parse.ftpauth import FTPAuth
from protocol_parse.httpall import HTTPProtocol
from protocol_parse.mongoauth import MongoDBAuth
from protocol_parse.mysqlauth import MySQLAuth
from protocol_parse.pgsqlauth import PGSQLAuth
from protocol_parse.rdpauth import RDPAuth
from protocol_parse.redisauth import RESPAuth
from protocol_parse.smtpauth import SMTPAuth
from protocol_parse.sshauth import SSHAuth

STREAM_DIRECT = {
    0: 'LOOP',
    1: 'OUT',
    2: 'IN',
    3: 'OTHER'

}


class StreamHandler(object):
    """

    """
    __END_STATES = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)
    istransip2long = True

    def __init__(self,
                 pcap_file=None,
                 device=None,
                 bpf_filter="tcp",
                 dst_tcp_port_filter=None,
                 dst_tcp_ip_filter=None,
                 src_tcp_port_filter=None,
                 src_tcp_ip_filter=None,
                 udp_port_filter=None,
                 udp_ip_filter=None,
                 data_level=1,
                 data_stream_direct=2,
                 std_output_enable=1,
                 file_output_path=None,
                 protocol_parse_conf=None,
                 is_handle_tcp=1,
                 is_handle_udp=1,
                 is_handle_ip=1,
                 sqlite3_output_enable=1,
                 sqlite3_output_path=None,
                 sqlite3_output_schema=None,
                 sqlite3_renew=False):
        """

        Args:
            pcap_file:
            device:
            bpf_filter:
            dst_port_filter:
            dst_ip_filter:
            src_port_filter:
            src_ip_filter:
            data_level:
            data_stream_direct:
            std_output_enable:
            file_tcpsession_path:
            protocol_parse_conf:
        """
        self.is_handle_tcp = is_handle_tcp
        self.is_handle_udp = is_handle_udp
        self.is_handle_ip = is_handle_ip

        self.bpf_filter = bpf_filter
        self.dst_tcp_port_filter = dst_tcp_port_filter
        self.dst_tcp_ip_filter = dst_tcp_ip_filter
        self.src_tcp_port_filter = src_tcp_port_filter
        self.src_tcp_ip_filter = src_tcp_ip_filter
        self.udp_ip_filter = udp_ip_filter
        self.udp_port_filter = udp_port_filter

        self.device = device
        self.pcap_file = pcap_file

        if pcap_file:
            nids.param("filename", pcap_file)
        elif device:
            nids.param("device", device)

        if bpf_filter:
            nids.param("pcap_filter", bpf_filter)  ## bpf restrict to TCP only, note

        self.data_level = data_level
        self.data_stream_direct = data_stream_direct

        self.std_output_enable = std_output_enable

        self.file_output_path = file_output_path

        self.protocol_parse_conf = protocol_parse_conf

        nids.param("scan_num_hosts", 0)  # disable portscan detection

        nids.chksum_ctl([('0.0.0.0/0', False)])  # disable checksumming

        nids.param("pcap_timeout", 64)
        nids.param("multiproc", 1)
        nids.param("tcp_workarounds", 1)

        # sqlite3 conf which store ip_handle statistic info
        self.sqlite3_output_enable = sqlite3_output_enable
        self.sqlite3_output_path = sqlite3_output_path
        self.sqlite3_output_schema = sqlite3_output_schema
        self.sqlite3_renew = sqlite3_renew

        # local ip
        if self.is_handle_ip:
            self.local_ip = networktools.get_local_ip(self.device)
        # var
        self.tcp_file_fh = None
        self.udp_file_fh = None
        self.ip_file_fh = None

        self.app_proto_fhs = {}

        if self.file_output_path:
            # 设置文件输出

            if os.path.exists(self.file_output_path) and os.path.isdir(self.file_output_path):
                # delete old data

                mills.rm_dir(self.file_output_path)

            os.mkdir(self.file_output_path)

            tcp_file_path = mills.path(self.file_output_path, "tcp.txt")
            self.tcp_file_fh = codecs.open(tcp_file_path,
                                           mode='wb',
                                           encoding='utf-8',
                                           errors='ignore')

            udp_file_path = mills.path(self.file_output_path, "udp.txt")
            self.udp_file_fh = codecs.open(udp_file_path,
                                           mode='wb',
                                           encoding='utf-8',
                                           errors='ignore')
            ip_file_path = mills.path(self.file_output_path, "ip.txt")
            self.ip_file_fh = codecs.open(ip_file_path,
                                          mode='wb',
                                          encoding='utf-8',
                                          errors='ignore')

            port_list = set()
            proto_list = set()
            for port_filter in [self.dst_tcp_port_filter, self.src_tcp_port_filter, self.udp_port_filter]:
                for port in port_filter:
                    port_list.add(port)

            for port in port_list:
                protocol = self.which_protocol_parse(port)

                if protocol:
                    proto_list.add(protocol)

            for protocol in proto_list:
                protocol_file_path = mills.path(self.file_output_path, "%s.txt" % protocol)
                protocol_file_fh = codecs.open(protocol_file_path,
                                               mode='wb',
                                               encoding='utf-8',
                                               errors='ignore')
                self.app_proto_fhs[protocol] = protocol_file_fh

    def __del__(self):

        if self.tcp_file_fh:
            self.tcp_file_fh.close()

        if self.udp_file_fh:
            self.udp_file_fh.close()

        if self.ip_file_fh:
            self.ip_file_fh.close()

        for app_proto, app_fh in self.app_proto_fhs.items():
            if app_fh:
                app_fh.close()
            # delete empty file
            protocol_file_path = mills.path(self.file_output_path, "%s.txt" % app_proto)

            if mills.isFileEmpty(protocol_file_path):
                os.remove(protocol_file_path)

    def run(self):
        """

        :return:
        """

        nids.init()

        if self.is_handle_tcp:
            nids.register_tcp(self.__handleTCPStream)

        if self.is_handle_udp:
            nids.register_udp(self.__handleUDPDatagram)

        if self.is_handle_ip:
            nids.register_ip(self.__handleIPPackets)
        # Loop forever (network device), or until EOF (pcap file)
        # Note that an exception in the callback will break the loop!
        try:

            nids.run()

        except nids.error as e:
            logging.error("[NIDS_RUN_Error]: %r" % e)
        except (KeyboardInterrupt, SystemExit) as e:
            logging.error("[System_Exit]: %r" % e)
        except Exception as e:
            logging.error("[NIDS RUN Exception]: %r %s" % (e, traceback.format_exc()))

    def exit(self):

        self.__del__()

    def __handleTCPStream(self, tcp):
        """

        :param tcp:
        :return:
        """

        global ts_start, ts_end

        ((src_ip, src_port), (dst_ip, dst_port)) = tcp.addr
        if self.dst_tcp_port_filter and dst_port not in self.dst_tcp_port_filter:
            return
        if self.dst_tcp_ip_filter and dst_ip not in self.dst_tcp_ip_filter:
            return
        if self.src_tcp_port_filter and src_port not in self.src_tcp_port_filter:
            return
        if self.src_tcp_ip_filter and src_ip not in self.src_tcp_ip_filter:
            return

        if tcp.nids_state == nids.NIDS_JUST_EST:
            if self.device:
                ts_start = mills.getCurrenttimestamp()
            else:
                ts_start = nids.get_pkt_ts()
            tcp.client.collect = 1
            tcp.server.collect = 1
        elif tcp.nids_state == nids.NIDS_DATA:
            if self.device:
                ts_end = mills.getCurrenttimestamp()
            else:
                ts_end = nids.get_pkt_ts()
            # keep all of the stream's new data
            tcp.discard(0)
            data_c2s = tcp.server.data[tcp.server.count - tcp.server.count_new:tcp.server.count]
            data_s2c = tcp.client.data[tcp.client.count - tcp.client.count_new:tcp.client.count]
            result = (ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, data_c2s, data_s2c)
            if self.data_stream_direct == 1:
                self.__outputTCP(result, direct=self.data_stream_direct, level=self.data_level)


        elif tcp.nids_state in StreamHandler.__END_STATES:
            if self.device:
                ts_end = mills.getCurrenttimestamp()
            else:
                ts_end = nids.get_pkt_ts()
            data_c2s_session = tcp.server.data[:tcp.server.count]
            data_s2c_session = tcp.client.data[:tcp.client.count]
            result = (ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, data_c2s_session, data_s2c_session)
            if self.data_stream_direct == 2:
                self.__outputTCP(result, direct=self.data_stream_direct, level=self.data_level)

    def __outputTCP(self, tcp_stream_data, direct=2, level=2):
        """

        :param tcp_stream_data:
        :param direct:
        :param level:
        :return:
        """

        if self.std_output_enable:
            # 标准输出
            self.__human_print_tcp(tcp_stream_data, direct=direct, level=level)
        if self.tcp_file_fh:
            # 文件输出
            self.__output_file(tcp_stream_data, self.tcp_file_fh)

        (_, _, _, _, _, dst_port, _, _) = tcp_stream_data
        protocol = self.which_protocol_parse(dst_port)

        if protocol:
            proto_fh = self.app_proto_fhs.get(protocol)
            if protocol == "smtp":
                self.__parse_data(SMTPAuth, tcp_stream_data, proto_fh)
            elif protocol == "ftp":
                self.__parse_data(FTPAuth, tcp_stream_data, proto_fh)
            elif protocol == "mysql":
                self.__parse_data(MySQLAuth, tcp_stream_data, proto_fh)
            elif protocol == "ssh":
                self.__parse_data(SSHAuth, tcp_stream_data, proto_fh)
            elif protocol == "pgsql":
                self.__parse_data(PGSQLAuth, tcp_stream_data, proto_fh)
            elif protocol == "redis":
                self.__parse_data(RESPAuth, tcp_stream_data, proto_fh)
            elif protocol == "mongodb":
                self.__parse_data(MongoDBAuth, tcp_stream_data, proto_fh)
            elif protocol == "rdp":
                self.__parse_data(RDPAuth, tcp_stream_data, proto_fh)
            elif protocol == "http":
                self.__parse_data(HTTPProtocol, tcp_stream_data, proto_fh)

    def __parse_data(self, proto_parse_class, data, file_hd):
        """

        Args:
            proto_parse_class:
            data:
            file_hd:

        Returns:

        """

        proto_parse_ob = proto_parse_class(data)
        data_yield = proto_parse_ob.parse_data(sep="\x00")
        for d in data_yield:
            if d:
                if file_hd:
                    file_hd.write("%r%s" % (d, os.linesep))
                if self.std_output_enable:
                    if not isinstance(d, dict):
                        d = d.toDict()
                    print json.dumps(d, indent=4)

    def __output_file(self, data, file_fh):
        """

        :param tcp_stream_data:
        :return:
        """
        # if tcp_stream_data contains unprintable char, ugly output to file
        file_fh.write("%s%s" % (data, os.linesep))

    def which_protocol_parse(self, dst_port):
        """

        :param tcp_stream_data:
        :return:
        """

        if self.protocol_parse_conf:
            for protocol, ports in self.protocol_parse_conf.items():
                if dst_port in ports:
                    return protocol

    def __human_print_tcp(self, tcp_stream_data, direct=2, level=2):
        """

        :param tcp_stream_data:
        :param direct:
        :param level:
        :return:
        """
        (ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, data_c2s, data_s2c) = tcp_stream_data
        if direct == 2:
            print "\n ********************[TCP DATA Bi-Direct]***************************************"
            print "[addr]: %s:%s %s:%s" % (src_ip, src_port, dst_ip, dst_port)
            print "[ts_start]: %s %s" % (ts_start, mills.timestamp2datetime(ts_start))
            print "[ts_end]: %s %s" % (ts_end, mills.timestamp2datetime(ts_end))
            print "[Data_Client_To_Server]: \n%s" % data_c2s
            if level > 1:
                print mills.str2hex2(data_c2s)
            print "[Data_Server_To_Client]: \n%s" % data_s2c
            if level > 1:
                print mills.str2hex2(data_s2c)
            print "***************************************************************************\n"
            return

        if direct == 1:
            print "\n *******************[TCP DATA One-Direct]****************************************"
            if data_s2c:
                print "{dst_ip}:{dst_port} ---------------------------------> {src_ip}:{src_port} ".format(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port
                )
            else:
                print "{src_ip}:{src_port} ---------------------------------> {dst_ip}:{dst_port} ".format(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port
                )
            print "[ts_start]: %s %s" % (ts_start, mills.timestamp2datetime(ts_start))
            print "[ts_end]: %s %s" % (ts_end, mills.timestamp2datetime(ts_end))
            print "[Data_Client_To_Server]: \n%s" % data_c2s
            if level > 1:
                print mills.str2hex2(data_c2s)
            print "[Data_Server_To_Client]: \n%s" % data_s2c
            if level > 1:
                print mills.str2hex2(data_s2c)
            print "***************************************************************************\n"
            return

    def __handleUDPDatagram(self, addrs, payload, pkt):
        """

        Args:
            addrs:
            payload:
            pkt:

        Returns:

        """
        global ts_start, ts_end

        ((src_ip, src_port), (dst_ip, dst_port)) = addrs

        if self.udp_port_filter and ((src_port not in self.udp_port_filter) and (dst_port not in self.udp_port_filter)):
            return

        if self.device:
            ts = mills.getCurrenttimestamp()
        else:
            ts = nids.get_pkt_ts()

        result = (ts, src_ip, src_port, dst_ip, dst_port, payload)

        self.__outputUDP(result, level=self.data_level)

    def __outputUDP(self, udp_datagram_data, level=2):
        """

        Args:
            udp_datagram_data:
            level:

        Returns:

        """
        if self.std_output_enable:
            self.__human_print_udp(udp_datagram_data, level=level)
        if self.udp_file_fh:
            self.__output_file(udp_datagram_data, self.udp_file_fh)
        (_, _, src_port, _, dst_port, data) = udp_datagram_data
        if src_port == 53 or dst_port == 53:
            proto_fh = self.app_proto_fhs.get("dns")
            self.__parse_data(DNSProtocol, udp_datagram_data, proto_fh)

    def __human_print_udp(self, udp_datagram, level=2):
        """

        Args:
            udp_datagram:
            level:

        Returns:

        """
        (ts, src_ip, src_port, dst_ip, dst_port, payload) = udp_datagram
        print "\n ********************[UDPDATA One-Direct]***************************************"
        print "[addr]: %s:%s %s:%s" % (src_ip, src_port, dst_ip, dst_port)
        print "[ts]: %s %s" % (ts, mills.timestamp2datetime(ts))
        print "[Data]: \n%s" % payload
        if level > 1:
            print mills.str2hex2(payload)
        print "***************************************************************************\n"
        return

    def __handleIPPackets(self, ip):
        # iptype



        # protocol type: tcp/udp/icmp/igmp/igrp/gre/esp/ah

        ts = nids.get_pkt_ts()

        try:
            iphdr = struct.unpack('!BBHHHBBH4s4s', ip[:20])
            ipproto = iphdr[6]
            ipsrc = socket.inet_ntoa(iphdr[8])
            ipdst = socket.inet_ntoa(iphdr[9])

            ipihl = iphdr[0] & 0xF
            ipihl *= 4  # ip header size

            # ipversion = iphdr[0] >> 4
            # iptos = iphdr[1]
            # iptotallen = iphdr[2]
            # ipid = iphdr[3]
            # ipttl = iphdr[5]

            if ipproto == 6 or ipproto == 17:
                tcpudphdr = struct.unpack('!HH', ip[ipihl:ipihl + 4])
                portsrc = tcpudphdr[0]
                portdst = tcpudphdr[1]
                len_of_ip = len(ip)

                # ip lookup
                try:
                    src_ip_geo = ip_lookup(ipsrc)
                except:
                    src_ip_geo = ""
                try:
                    dst_ip_geo = ip_lookup(ipdst)
                except:
                    dst_ip_geo = ""

                # port lookup
                p = PortServiceMap()
                src_port_service = p.lookup(portsrc)
                dst_port_service = p.lookup(portdst)

                # special is a in/out network commucation

                if ipsrc == self.local_ip:
                    if ipdst == self.local_ip:
                        direct = 0  # loop
                    else:
                        direct = 1  # out
                elif ipdst == self.local_ip:
                    direct = 2  # in
                else:
                    direct = 3  # other

                # tcp
                if ipproto == 6:
                    tcphdr = struct.unpack('!LLBBHHH', ip[ipihl + 4:ipihl + 20])
                    tcpseq = tcphdr[0]
                    tcpack = tcphdr[1]

                    tcpoffset = tcphdr[2] >> 4
                    tcphl = tcpoffset * 4  # tcp header size

                    tcpflags = tcphdr[3]
                    tcpwindow = tcphdr[4]

                    tcpflagsstr = convert(tcpflags)
                    tcpflagsstr = ",".join(tcpflagsstr)

                    len_of_data = len_of_ip - ipihl - tcphl
                    # data=ip[ipihl+tcphl:]

                    result = direct, \
                             ts, \
                             ipproto, ipsrc, ipdst, \
                             portsrc, portdst, \
                             len_of_ip, \
                             src_ip_geo, dst_ip_geo, \
                             src_port_service, dst_port_service, tcpseq, tcpack, tcpflagsstr, tcpwindow, \
                             len_of_data

                else:
                    len_of_data = len_of_ip - ipihl - 8  # UDP Header:8
                    # data=ip[ipihl+8:]

                    result = direct, \
                             ts, \
                             ipproto, ipsrc, ipdst, \
                             portsrc, portdst, \
                             len_of_ip, \
                             src_ip_geo, dst_ip_geo, \
                             src_port_service, dst_port_service, \
                             len_of_data

                self.__outputIP(result)
        except Exception as e:
            logging.error(e)

    def __outputIP(self, ip_statistic_tuple):
        """

        Args:
            ip_statistic_tuple:

        Returns:

        """
        if self.std_output_enable:
            self.__human_print_ip(ip_statistic_tuple)
        if self.ip_file_fh:
            result = "\t".join([str(item).strip() for item in ip_statistic_tuple])
            self.__output_file(result, self.ip_file_fh)
        if self.sqlite3_output_enable:
            self.__output_sqlite3(ip_statistic_tuple)

    def __human_print_ip(self, ip_statistic_tuple):
        """

        Args:
            ip_statistic_tuple:

        Returns:

        """
        if len(ip_statistic_tuple) == 13:

            (direct, ts, ip_protocol_type, src_ip, dst_ip, src_port, dst_port, length,
             src_ip_geo, dst_ip_geo, src_port_service, dst_port_service, len_of_data) = ip_statistic_tuple
            ts = mills.timestamp2datetime(ts)
            ip_protocol_type = "UDP"
            result = "{direct}\t{ts}\t{ip_protocol_type}\t{src_ip}:{src_port}({src_ip_geo})({src_port_service})" \
                     "\t{dst_ip}:{dst_port}({dst_ip_geo})({dst_port_service})\tPACKET_LENGTH={length}" \
                     "\tDATA_LENGTH={len_of_data}".format(
                direct=STREAM_DIRECT.get(direct, direct),
                ts=ts,
                ip_protocol_type=ip_protocol_type,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                length=length,
                src_ip_geo=src_ip_geo,
                dst_ip_geo=dst_ip_geo,
                src_port_service=src_port_service,
                dst_port_service=dst_port_service,
                len_of_data=len_of_data
            )


        else:

            (direct,
             ts,
             ip_protocol_type,
             src_ip, dst_ip,
             src_port, dst_port,
             length,
             src_ip_geo, dst_ip_geo,
             src_port_service, dst_port_service,
             tcpseq, tcpack, tcpflagsstr, tcpwindow, len_of_data) = ip_statistic_tuple

            ip_protocol_type = "TCP"

            ts = mills.timestamp2datetime(ts)
            result = "{direct}\t{ts}\t{ip_protocol_type}\t{src_ip}:{src_port}({src_ip_geo})({src_port_service})" \
                     "\t{dst_ip}:{dst_port}({dst_ip_geo})({dst_port_service})\tPACKET_LENGTH={length}" \
                     "\tDATA_LENGTH={len_of_data}" \
                     "\tSEQ={tcpseq}\tACK={tcpack}\tFLAGS={tcpflagsstr}\tWINDOW={tcpwindow}".format(
                direct=STREAM_DIRECT.get(direct, direct),
                ts=ts,
                ip_protocol_type=ip_protocol_type,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                length=length,
                src_ip_geo=src_ip_geo,
                dst_ip_geo=dst_ip_geo,
                src_port_service=src_port_service,
                dst_port_service=dst_port_service,
                tcpseq=tcpseq,
                tcpack=tcpack,
                tcpflagsstr=tcpflagsstr,
                tcpwindow=tcpwindow,
                len_of_data=len_of_data
            )

        print result

    def __output_sqlite3(self, ip_statistic_tuple):
        """

        Args:
            ip_statistic_tuple:
            sqliteconf:

        Returns:

        """

        if not (self.sqlite3_output_path and os.path.exists(self.sqlite3_output_path)):
            self.sqlite3_output_path = mills.path("data/ip_packet/ip_statistic.db")
            self.sqlite3_renew = True

        if not (self.sqlite3_output_schema and os.path.exists(self.sqlite3_output_schema)):
            self.sqlite3_output_schema = mills.path("data/ip_packet/ip_statistic.sql")

        so = SQLiteOper(dbpath=self.sqlite3_output_path, db_is_new=bool(self.sqlite3_renew))

        # 创建表
        so.createTable(self.sqlite3_output_schema)
        fields = ["direct",
                  "ts",
                  "ip_protocol_type",
                  "src_ip", "dst_ip",
                  "src_port", "dst_port",
                  "packet_length",
                  "src_ip_geo", "dst_ip_geo",
                  "src_port_service", "dst_port_service"]
        data_dict = dict(zip(fields, ip_statistic_tuple[0:12]))

        so.replaceData2SQLite3(op='insert', tablename='ip_statistic_tuple', fields=fields, data_dict=data_dict)


TCP_FLAG_DICT = OrderedDict(
    [("128", "CWR"), ("64", "ECE"), ("32", "URG"), ("16", "ACK"), ("8", "PSH"), ("4", "RST"), ("2", "SYN"),
     ("1", "FIN")])


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
