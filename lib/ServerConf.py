# -*- coding: utf-8 -*-
import codecs
import logging

from yaml import load

import mills


class ServerConf(object):
    """
    server 配置对象
    """

    def __init__(self, rulefname):
        """

        :param rulefname: 配置文件路径
        """
        self.__rulefd = None
        try:
            self.__rulefd = codecs.open(rulefname, mode='rb', encoding='utf8', errors='ignore')
        except Exception as e:
            logging.error("read %s file failed: %s" % (rulefname, repr(e)))

        dataMap = load(self.__rulefd)
        stream_handler = dataMap.get("stream_handler")
        self.is_handle_tcp = stream_handler.get("is_handle_tcp", 0)
        self.is_handle_udp = stream_handler.get("is_handle_udp", 0)
        self.is_handle_ip = stream_handler.get("is_handle_ip", 0)

        self.bpf_filter = stream_handler.get("bpf_filter")
        self.dst_tcp_port_filter = stream_handler.get("dst_tcp_port_filter")
        self.dst_tcp_ip_filter = stream_handler.get("dst_tcp_ip_filter")
        self.src_tcp_port_filter = stream_handler.get("src_tcp_port_filter")
        self.src_tcp_ip_filter = stream_handler.get("src_tcp_ip_filter")
        self.udp_port_filter = stream_handler.get("udp_port_filter")
        self.udp_ip_filter = stream_handler.get("udp_ip_filter")

        self.pcap_file = stream_handler.get("pcap_file") if stream_handler.get("pcap_file_enable",
                                                                               0) == 1 else None

        if self.pcap_file:
            self.pcap_file = mills.path(self.pcap_file)

        self.device = stream_handler.get("device") if stream_handler.get("device_enable",
                                                                         0) == 1 else None

        self.data_level = stream_handler.get("data_level", 1)
        self.data_stream_direct = stream_handler.get("data_stream_direct", 2)
        self.std_output_enable = stream_handler.get("std_output_enable", 1)

        self.file_output_path = stream_handler.get("file_output_path") if stream_handler.get(
            "file_output_enable",
            0) == 1 else None

        if self.file_output_path:
            self.file_output_path = mills.path(self.file_output_path)

        self.sqlite3_output_enable = stream_handler.get("sqlite3_output_enable", 0)
        self.sqlite3_output_path = stream_handler.get("sqlite3_output_path")
        self.sqlite3_output_schema = stream_handler.get("sqlite3_output_schema")
        self.sqlite3_renew = stream_handler.get("sqlite3_renew", 0)

        self.protocol_parse_conf = stream_handler.get("protocol_parse_conf")

    def __del__(self):
        if self.__rulefd:
            self.__rulefd.close()
