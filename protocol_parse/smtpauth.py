# -*- coding: utf-8 -*-
# http://blog.csdn.net/bripengandre/article/details/2191048
import logging
import re

import lib.mills as mills
from lib.PasswdCrackOb import PassWdCrackOb


class SMTPAuth(object):
    """
    parse smtp auth protocol
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

        (is_both, auth_detail) = self.__parse_client_data()
        auth_result = self.__parse_server_data()

        if auth_detail and auth_result:

            if is_both == 1:
                # 账号密码同时传输
                if len(auth_detail) == len(auth_result):

                    while auth_result and auth_detail:
                        crack_result = auth_result.pop()

                        crack_detail = auth_detail.pop()
                        crack_detail = mills.is_base64(crack_detail)
                        if crack_detail:
                            pcci = PassWdCrackOb(service="smtp",
                                                 src_ip=self.src_ip,
                                                 src_port=self.src_port,
                                                 dst_ip=self.dst_ip,
                                                 dst_port=self.dst_port,
                                                 crack_result=crack_result,
                                                 crack_detail=crack_detail,
                                                 ts_start=self.ts_start,
                                                 ts_end=self.ts_end)
                            yield pcci

            if is_both == 0:
                # 账号密码分开传输
                len_of_auth_detail = len(auth_detail)

                if len_of_auth_detail % 2 == 0 and (2 * len(auth_result) == len_of_auth_detail):
                    while auth_result and auth_detail:
                        crack_result = auth_result.pop()
                        crack_passwd = auth_detail.pop()
                        crack_user = auth_detail.pop()
                        crack_passwd = mills.is_base64(crack_passwd)
                        crack_user = mills.is_base64(crack_user)

                        crack_detail = "%s%s%s%s" % (sep, crack_user, sep, crack_passwd)
                        pcci = PassWdCrackOb(service="smtp",
                                             src_ip=self.src_ip,
                                             src_port=self.src_port,
                                             dst_ip=self.dst_ip,
                                             dst_port=self.dst_port,
                                             crack_result=crack_result,
                                             crack_detail=crack_detail,
                                             ts_start=self.ts_start,
                                             ts_end=self.ts_end)
                        yield pcci
        else:
            logging.error("[SMTP_ODD_DATA]: %s" % repr(self.data_tuple))

    def __parse_server_data(self):
        """

        :return:
        """
        # response_code+\s+param+\r\n
        # 2:success
        # 4/5:failed
        # 3:un-finished
        auth_result = []

        parts = self.__split_smtp_data(self.data_s2c)
        server_data_pattern = re.compile(r'^(\d{3})\s(.+)$')
        for p in parts:
            m = re.match(server_data_pattern, p)
            if m is not None:
                (command_code, param) = m.groups()

                if command_code.startswith('5'):
                    # http://blog.csdn.net/chenfei_5201213/article/details/10138969
                    if command_code == "535":
                        auth_result.append(2)
                    else:
                        # 554 IP is rejected,
                        # smtp auth error limit exceed,
                        # 126 smtp3,DcmowAAHjJkIJ1JZiXLTJg--.50667S0 1498556168
                        # 550
                        auth_result.append(3)
                elif command_code == '235' and param.find("Authentication successful") != -1:
                    auth_result.append(1)
        return auth_result

    def __parse_client_data(self):
        """

        :return:
        """
        # command+\s+[param]+\r\n
        # AUTH PLAIN AHRlc3QAdGVzdA== base64decode(emailpass)
        #
        auth_detail = []
        parts = self.__split_smtp_data(self.data_c2s)

        client_data_parttern = re.compile(r'^(AUTH)?\s?(.+)')

        is_both = 0
        for p in parts:
            m = re.match(client_data_parttern, p)
            if m is not None:
                (command, param) = m.groups()

                if command == "AUTH":

                    pos = param.find("PLAIN")

                    if pos != -1:
                        is_both = 1
                        account = param[pos + 6:]

                        auth_detail.append(account)
                elif command is None:
                    len_of_param = len(param)
                    if len_of_param > 4 and len_of_param % 4 == 0:
                        auth_detail.append(param)

        return (is_both, auth_detail)

    def __split_smtp_data(self, data):
        """
        splite packets-str to packet list
        :param data:
        :return:
        """
        ftp_data_list = []
        try:
            ftp_data_list = data.split("\r\n")
        except Exception as e:
            logging.error("[SPLIT_SMTP_DATA_FAILED]: %s %r" % (data, e))

        return ftp_data_list
