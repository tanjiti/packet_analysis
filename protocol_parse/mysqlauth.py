# -*- coding: utf-8 -*-
# http://hutaow.com/blog/2013/11/06/mysql-protocol-analysis/
import logging

import lib.mills as mills
from lib.PasswdCrackOb import PassWdCrackOb


class MySQLAuth(object):
    """
    parse mysql auth protocol
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

        # var
        self.is_ssl = False

    def parse_data(self, sep='\x00'):
        """

        :param sep:
        :return:
        """

        if not (self.data_c2s and self.data_s2c):
            return

        auth_detail = self.__parse_client_data(sep=sep)
        auth_result = self.__parse_server_data()
        auth_detail.reverse()
        auth_result.reverse()

        if auth_detail and auth_result:

            if len(auth_detail) == len(auth_result):

                while auth_result and auth_detail:
                    crack_result = auth_result.pop()

                    crack_detail = auth_detail.pop()

                    if crack_detail:
                        pcci = PassWdCrackOb(service="mysql",
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
            if not self.is_ssl:
                logging.error("[MYSQL_ODD_DATA]: %s" % repr(self.data_tuple))

    def __parse_server_data(self):
        """

        :return:
        """

        auth_result = []
        for item in self.__split_mysql_data(self.data_s2c):
            # 1 find Response
            len_of_data_c2s = len(item)

            if len_of_data_c2s < 4:
                continue
            packetnumber = item[3]
            # make sure the packet number is 1
            if packetnumber != "02":
                continue
            status_code = item[4]
            if status_code == "00":
                auth_result.append(1)
            elif status_code == "ff":
                auth_result.append(2)
            else:
                continue

        return auth_result

    def __parse_client_data(self, sep='\x00'):
        """

        :return:
        """

        auth_detail = []

        data_c2s_data_list = self.__split_mysql_data(self.data_c2s)
        for item in data_c2s_data_list:
            # 1. find Login Request
            len_of_data_c2s = len(item)

            if len_of_data_c2s < 36:
                # packet header: 4
                # client capabilities: 4
                # max packet: 4
                # charset: 1
                # reserved : 23

                continue

            packetnumber = item[3]
            # make sure the packet number is 1
            if packetnumber != "01":
                continue
            # make sure the reserved  23 byte is all 00
            is_reserved_ok = 1

            for i in item[13:36]:
                if i != "00":
                    is_reserved_ok = 0
                    break
            if is_reserved_ok != 1:
                continue

            client_capabilities = bin(int("".join([item[5], item[4]]), base=16))
            is_ssl = client_capabilities[-12]
            # check is connect db
            is_connect_db = client_capabilities[-4]

            # check if swith to ssl after handshake
            if len_of_data_c2s == 36:

                if is_ssl == '1':
                    self.is_ssl = True
                    logging.debug(
                        "[MYSQL_SSL]: %s:%s -> %s:%s %f %f" % (self.src_ip, self.src_port, self.dst_ip,
                                                               self.dst_port, self.ts_start, self.ts_end))

                continue
            # get the user name
            # string end with 00
            user = ""
            db = ""

            pos_00 = 0
            for i in range(36, len_of_data_c2s):
                if item[i] == "00":
                    pos_00 = i
                    break
                user = user + chr(int(item[i], base=16))

            len_of_passwd = int(item[pos_00 + 1], base=16)

            passwd = ""

            if len_of_passwd > 0:
                passwd = "".join(item[pos_00 + 2:pos_00 + 2 + len_of_passwd + 1])

            if is_connect_db == '1':
                pos_of_db = pos_00 + 1 + len_of_passwd + 1
                for i in range(pos_of_db, len_of_data_c2s):
                    if item[i] == "00":
                        break
                    db = db + chr(int(item[i], base=16))

            # user/database_name
            crack_detail = "%s%s%s%s%s%s" % (sep, user, sep, passwd, sep, db)
            auth_detail.append(crack_detail)

        return auth_detail

    def __split_mysql_data(self, data):
        """
        splite packets-str to packet list
        :param data:
        :return:
        """
        mysql_data_list = []
        chrs = mills.str2hex(data, return_str=False)

        len_of_chrs = len(chrs)
        offset = 0

        while offset < len_of_chrs:
            # 前三个字节表示长度，第四个字节表示序列号, 小端字节序

            first_3_offset = chrs[offset:offset + 3]
            len_of_packet_str = "".join(reversed(first_3_offset))

            len_of_packet_str = "%s" % len_of_packet_str

            try:
                len_of_packet = int(len_of_packet_str, base=16)
                next_offset = offset + len_of_packet + 4
                data_item = chrs[offset:next_offset]

                mysql_data_list.append(data_item)
                offset = next_offset
            except Exception as e:
                logging.error("[PACKET_LENGTH_COMPUTER_FAILED]: %r" % e)
                return mysql_data_list

        return mysql_data_list
