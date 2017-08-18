# -*- coding: utf-8 -*-
# http://blog.csdn.net/yxyhack/article/details/1826256
import logging
import re

from lib.PasswdCrackOb import PassWdCrackOb


class FTPAuth(object):
    """
    parse ftp auth protocol
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

        # print auth_detail,auth_result


        if auth_detail and auth_result:

            auth_detail.reverse()
            auth_result.reverse()

            len_of_auth_detail = len(auth_detail)

            if len_of_auth_detail % 2 == 0 and (2 * len(auth_result) == len_of_auth_detail):
                while auth_result and auth_detail:
                    crack_result = auth_result.pop()
                    crack_user = auth_detail.pop()
                    crack_passwd = auth_detail.pop()

                    crack_detail = "%s%s%s%s" % (sep, crack_user, sep, crack_passwd)

                    pcci = PassWdCrackOb(service="ftp",
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

            logging.error("[FTP_ODD_DATA]: %s" % repr(self.data_tuple))

    def __parse_server_data(self):
        """

        :return:
        """
        # response_code+\s+param+\r\n
        # 2:success
        # 4/5:failed 530 Login incorrect.
        # 3:un-finished
        auth_result = []
        if not self.data_s2c:
            return auth_result

        parts = self.__split_ftp_data(self.data_s2c)
        server_data_pattern = re.compile(r'^(\d{3})\s(.+)')

        response_code_list = []
        i = -1  # index of response_code

        for p in parts:
            m = re.match(server_data_pattern, p)
            if m is not None:
                (command_code, param) = m.groups()

                response_code_list.append(command_code)
                i = i + 1

                if command_code.startswith('5'):

                    if command_code == "530" and response_code_list[i - 1] != "530":
                        auth_result.append(2)
                    elif command_code != "530":
                        auth_result.append(3)
                elif command_code == '230':
                    auth_result.append(1)

        return auth_result

    def __parse_client_data(self):
        """

        :return:
        """
        # command+\s+[param]+\r\n
        #
        auth_detail = []
        if not self.data_c2s:
            return auth_detail

        parts = self.__split_ftp_data(self.data_c2s)

        client_data_parttern = re.compile(r'^(USER|PASS)\s(.+)')

        for p in parts:
            m = re.match(client_data_parttern, p)
            if m is not None:
                (command, param) = m.groups()

                auth_detail.append(param)

        return auth_detail

    def __split_ftp_data(self, data):
        """
        splite packets-str to packet list
        :param data:
        :return:
        """

        ftp_data_list = []
        try:
            ftp_data_list = data.split("\r\n")
        except Exception as e:
            logging.error("[SPLIT_FTP_DATA_FAILED]: %s %r" % (data, e))

        return ftp_data_list
