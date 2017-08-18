# -*- coding: utf-8 -*-
# https://www.postgresql.org/docs/current/static/protocol.html
# https://www.postgresql.org/docs/current/static/protocol-message-formats.html
# http://www.postgres.cn/docs/9.4/auth-pg-hba-conf.html
import logging

import lib.mills as mills
from lib.PasswdCrackOb import PassWdCrackOb


class PGSQLAuth(object):
    """
    parse pgsql auth protocol
    """
    __PGSQL_COMMAND_CODE = {
        '52': 'Authentication Request',  # Notice
        '4b': 'BackendKeyData',
        '42': 'Bind',
        '32': 'BindComplete',
        '43': 'Close/CommandComplete',
        '33': 'CloseComplete',
        '64': 'CopyData',
        '63': 'CopyDone',
        '66': 'CopyFail',
        '47': 'CopyInResponse',
        '48': 'CopyOutResponse/Flush',
        '57': 'CopyBothResponse',
        '44': 'DataRow/Describe',
        '49': 'EmptyQueryResponse',
        '45': 'ErrorResponse/Execute',
        '46': 'FunctionCall',
        '56': 'FunctionCallResponse',
        '6e': 'NoData',
        '4e': 'NoticeResponse',
        '41': 'NotificationResponse',
        '74': 'ParameterDescriptio',
        '53': 'ParameterStatus/Sync',
        '50': 'Parse',
        '31': 'ParseComplete',
        '70': 'PasswordMessage',  # Notice
        '73': 'PortalSuspended',
        '51': 'Query',
        '5a': 'ReadyForQuery',
        '54': 'RowDescription',
        '58': 'Terminate'

    }
    __AUTH_CODE = {
        '00': 'Successful',
        '02': 'KererosV5',
        '03': 'CleartextPassword',
        '05': 'MD5Password',
        '06': 'SCMCredential',
        '07': 'GSSAPI',
        '09': 'SSPI',
        '08': 'GSSAPI/SSPI'

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

    def parse_data(self, sep='\x00'):
        """

        :param sep:
        :return:
        """
        if not (self.data_c2s and self.data_s2c):
            return

        auth_detail = self.__parse_client_data()
        auth_result = self.__parse_server_data()

        if auth_detail and auth_result:

            auth_result_dict = {}
            len_auth_detail = len(auth_detail)

            i = 0

            for i in range(i, len_auth_detail, 2):
                auth_result_dict[auth_detail[i]] = auth_detail[i + 1]

            if len(auth_result) == 1:

                crack_detail = "{sep}{user}{sep}{password}{sep}{database}".format(
                    sep=sep,
                    user=auth_result_dict.get("user"),
                    database=auth_result_dict.get("database"),
                    password=auth_result_dict.get("password", "NONE_%d" % mills.getCurrenttimestamp())
                )

                if PGSQLAuth.__AUTH_CODE[auth_result[0]] == "Successful":
                    crack_result = 1
                else:
                    crack_result = 2

                pcci = PassWdCrackOb(service="pgsql",
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
            logging.error("[PGSQL_ODD_DATA]: %s" % repr(self.data_tuple))

    def __parse_server_data(self):
        """

        :return:
        """

        auth_result = []
        data_s2c_list = self.__split_pqsql_data(self.data_s2c)
        for item in data_s2c_list:
            # find startup message
            # 前四位表示长度 + 两位表示大版本号 + 两位小版本号 + 名/值对（用00分割）

            first = item[0]

            if first in PGSQLAuth.__PGSQL_COMMAND_CODE:
                # Authentication Request

                if first == "52" and item[5:8] == ["00", "00", "00"]:
                    # Authentication Type
                    auth_type = item[8]
                    auth_result.append(auth_type)

        return auth_result

    def __parse_client_data(self):
        """

        :return:
        """

        auth_detail = []
        data_c2s_list = self.__split_pqsql_data(self.data_c2s)
        for item in data_c2s_list:
            # find startup message
            # 前四位表示长度 + 两位表示大版本号 + 两位小版本号 + 名/值对（用00分割）
            len_of_item = len(item)
            first = item[0]

            if first not in PGSQLAuth.__PGSQL_COMMAND_CODE:
                # startupmessage/sslrequest/cancelrequest
                # 获得版本号

                if item[4:8] == ["00", "03", "00", "00"]:
                    # startupmessage协议
                    param = []
                    i = 8
                    while i < len_of_item - 1:

                        if item[i] == "00":

                            param_value = "".join(param)
                            auth_detail.append(param_value)
                            param = []

                        else:
                            param.append(chr(int(item[i], base=16)))
                        i = i + 1

            else:

                if first == "70":
                    # Password message
                    len_of_passwd_str = "".join(item[1:5])
                    len_of_passwd = int(len_of_passwd_str, base=16)

                    passwd_chr_list = item[5:len_of_passwd]
                    passwd_chr_list = [chr(int(ch, base=16)) for ch in passwd_chr_list]
                    passwd_chr_str = "".join(passwd_chr_list)
                    auth_detail.append("password")
                    auth_detail.append(passwd_chr_str)

        if len(auth_detail) % 2 != 0:
            auth_detail = []
        return auth_detail

    def __split_pqsql_data(self, data):
        """
        splite packets-str to packet list
        :param data:
        :return:
        """
        pqsql_data_list = []
        chrs = mills.str2hex(data, return_str=False)

        len_of_chrs = len(chrs)

        offset = 0

        while offset < len_of_chrs:
            # https://www.postgresql.org/docs/current/static/protocol-message-formats.html

            # 协议格式一: 第一个字节表示命令类型，接着四个字节表示消息长度，包括自身
            # 协议格式二：前四个字节表示消息长度，包括自身
            #  字节序采用：大端字节序

            try:
                first_chr = chrs[offset]
                if first_chr in PGSQLAuth.__PGSQL_COMMAND_CODE.keys():
                    # 第一种格式
                    len_of_packet_str = chrs[offset + 1:offset + 5]
                    len_of_packet_str = "".join(len_of_packet_str)
                    len_of_packet = int(len_of_packet_str, base=16)
                    next_offset = offset + len_of_packet + 1

                else:
                    # 第二种格式
                    len_of_packet_str = chrs[offset:offset + 4]
                    len_of_packet_str = "".join(len_of_packet_str)
                    len_of_packet = int(len_of_packet_str, base=16)
                    next_offset = offset + len_of_packet

                data_item = chrs[offset:next_offset]
                pqsql_data_list.append(data_item)
                offset = next_offset







            except Exception as e:
                logging.error("[PACKET_LENGTH_COMPUTER_FAILED]: %r" % e)
                return pqsql_data_list

        return pqsql_data_list
