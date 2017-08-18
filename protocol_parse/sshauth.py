# -*- coding: utf-8 -*-
# http://blog.csdn.net/macrossdzh/article/details/5691924
import logging
import re

from lib.PasswdCrackOb import PassWdCrackOb


class SSHAuth(object):
    """
    parse ssh auth protocol
    """

    def __init__(self,
                 data_tuple
                 ):
        """

        :param data_tuple:
        """
        (ts_start, ts_end, src_ip, src_port, dst_ip, dst_port, data_c2s, data_s2c) = data_tuple
        self.data_tuple = data_tuple
        self.ts_start = ts_start
        self.ts_end = ts_end
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.data_c2s = data_c2s
        self.data_s2c = data_s2c

    def parse_data(self, sep='\x00'):
        """

        :param sep:
        :return:
        """
        if not (self.data_c2s and self.data_s2c):
            return

        auth_detail = self.__parse_client_data()
        auth_result = self.__parse_server_data()
        auth_detail.reverse()
        auth_result.reverse()

        if auth_detail and auth_result:

            if len(auth_detail) == len(auth_result):
                while auth_result and auth_detail:
                    timetag = "%s-%s" % (self.ts_start, self.ts_end)
                    crack_detail = "%s%s%s%s%s%s" % (sep, auth_detail.pop(), sep, auth_result.pop(), sep, timetag)

                    pcci = PassWdCrackOb(service="ssh",
                                         src_ip=self.src_ip,
                                         src_port=self.src_port,
                                         dst_ip=self.dst_ip,
                                         dst_port=self.dst_port,
                                         crack_result=-1,
                                         crack_detail=crack_detail,
                                         ts_start=self.ts_start,
                                         ts_end=self.ts_end)
                    yield pcci
        else:
            logging.error("[SSH_ODD_DATA]: %s" % repr(self.data_tuple))

    def __parse_server_data(self):
        """

        :return:
        """
        # 版本号协商
        # SSH－<主协议版本号>.<次协议版本号>－<软件版本号>
        # SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8

        auth_result = []
        parts = self.data_s2c.split("\r\n")
        server_data_pattern = re.compile(r'^SSH-\d+\.\d+-.+$')
        for p in parts:

            m = re.match(server_data_pattern, p)

            if m is not None:
                auth_result.append(p)

        return auth_result

    def __parse_client_data(self):
        """

        :return:
        """
        # 版本号协商
        # SSH－<主协议版本号>.<次协议版本号>－<软件版本号>
        # SSH-2.0-paramiko_2.1.2

        auth_detail = []
        parts = self.data_c2s.split("\r\n")

        client_data_parttern = re.compile(r'^SSH-\d+\.\d+-.+$')

        for p in parts:

            m = re.match(client_data_parttern, p)

            if m is not None:
                auth_detail.append(p)

        return auth_detail
