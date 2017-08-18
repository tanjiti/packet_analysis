# -*- coding: utf-8 -*-
# https://redis.io/topics/protocol
import logging

from lib.PasswdCrackOb import PassWdCrackOb


class RESPAuth(object):
    """
    parse redis auth protocol
    """
    __RESP_DATA_TYPE = {
        '+': 'Simple Strings',
        '-': 'Errors',
        ':': 'Integers',
        '$': 'Bulk Strings',
        '*': 'Arrays'
    }

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

    def parse_data(self, sep="\x00"):
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

            if len(auth_result) <= len(auth_detail):
                while auth_detail and auth_result:
                    crack_detail = auth_detail.pop()
                    crack_result = auth_result.pop()

                    pcci = PassWdCrackOb(service="redis",
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
            logging.error("[REDIS_ODD_DATA]: %s" % repr(self.data_tuple))

    def __parse_server_data(self):
        """

        :return:
        """

        auth_result = []
        data_s2c_list = self.__split_redis_data(self.data_s2c)

        len_of_data_s2c = len(data_s2c_list)
        index = 0
        while index < len_of_data_s2c:

            if data_s2c_list[index] == "-ERR invalid password":
                auth_result.append(2)  # 2:not ok

            elif data_s2c_list[index] == "+OK":
                auth_result.append(1)
                break

            elif data_s2c_list[index].startswith("-ERR"):
                index = index + 1
                continue
            else:
                break
            index = index + 1
        # print data_s2c_list, auth_result

        return auth_result

    def __parse_client_data(self):
        """

        :return:
        """

        auth_detail = []
        data_c2s_list = self.__split_redis_data(self.data_c2s)

        len_of_data_c2s = len(data_c2s_list)
        index = 0
        while index < len_of_data_c2s:

            if data_c2s_list[index] == "*2" and len(data_c2s_list[index:]) > 5:
                if data_c2s_list[index + 1] == "$4" and data_c2s_list[index + 2].lower() == "auth":
                    passwd = data_c2s_list[index + 4]
                    auth_detail.append(passwd)
                index = index + 5

            else:
                index = index + 1
        # print data_c2s_list, auth_detail
        return auth_detail

    def __check_type_RESP(self, item):
        """

        Args:
            item:

        Returns:

        """
        if len(item) > 1:
            data_type = RESPAuth.__RESP_DATA_TYPE.get(item[0])
            return data_type

    def __split_redis_data(self, data):
        """
        splite packets-str to packet list
        :param data:
        :return:
        """
        redis_data_list = []
        try:
            redis_data_list = data.split("\r\n")
        except Exception as e:
            logging.error("[SPLIT_REDIS_DATA_FAILED]: %s %r" % (data, e))

        return redis_data_list
