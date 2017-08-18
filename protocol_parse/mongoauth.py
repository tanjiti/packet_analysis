# -*- coding: utf-8 -*-
# https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/
import logging
from collections import OrderedDict

import lib.mills as mills
from lib.PasswdCrackOb import PassWdCrackOb


class MongoDBAuth(object):
    """
    parse pgsql auth protocol
    """
    __MONGODB_OPCODE = {
        1: 'REPLY',  # FromServer: OP_REPLY is reserved for use by the database.
        2004: 'QUERY'  # FromClient: Only the OP_QUERY and OP_GET_MORE messages result in a response from the database

    }
    # https://cs.fit.edu/code/svn/cse2410f13team7/wireshark/epan/dissectors/packet-mongo.c
    __DOCUMENT_DATA_TYPE = {
        '10': 'int32',  # 四个字节
        '03': 'document',  # length
        '02': 'string',  # length
        '05': 'binary',  # length
        '08': 'boolean',  # 一个字节
        '09': 'datetime',  # 八个字节
        '01': 'double',  # 八个字节
        '04': 'array',
        '12': 'int64',  # 八个字节
        '11': 'timestamp',

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
        auth_detail.reverse()
        auth_result.reverse()

        if auth_detail and auth_result:

            # 账号密码同时传输
            if len(auth_detail) == len(auth_result):

                while auth_result and auth_detail:
                    crack_result = auth_result.pop()

                    crack_detail = auth_detail.pop()

                    if crack_detail:
                        pcci = PassWdCrackOb(service="mongodb",
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
            if auth_detail or auth_result:
                logging.error("[MongoDB_ODD_DATA]: %s" % repr(self.data_tuple))

    def __parse_server_data(self):
        """

        :return:
        """

        auth_result = []
        data_s2c_list = self.__split_mongo_data(self.data_s2c)
        for item in data_s2c_list:
            # https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/#wire-op-reply
            # 协议格式
            # messageLength 4
            # requestID 4
            # responseTo 4
            # opCode 4

            opcode = self.__chrs2int(item[12:12 + 4])
            if opcode != 1:
                continue
            # op_reply格式
            # flags 4
            # cursorID 8
            # startingFrom 4
            # numberReturned 4
            # document 变长
            documents = item[36:]
            document_result = self.__parse_document(documents)
            # print "server2clientData:",document_result
            if document_result.get("ok", 1) == 0 \
                    and document_result.get("code", 0) == 18 \
                    and document_result.get("codeName") == "AuthenticationFailed":
                auth_result.append(2)
            else:
                if document_result.get("done", "00") == "01":
                    auth_result.append(1)
        # print "auth_result:",auth_result
        return auth_result

    def __parse_client_data(self, sep="\x00"):
        """

        :return:
        """

        auth_detail = []
        data_c2s_list = self.__split_mongo_data(self.data_c2s)
        for item in data_c2s_list:
            # https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/#wire-op-query
            # 协议格式
            # messageLength 4
            # requestID 4
            # responseTo 4
            # opCode 4

            opcode = self.__chrs2int(item[12:12 + 4])
            if opcode != 2004:
                continue
            # op_query格式
            # flags 4
            # fullCollectionName dbname.collectionname 变长
            # numberToSkip 4
            # numberToReturn 4
            # document 变长
            # 获得fullcollectionname

            fullcollectionname = []
            i = 20
            while i < len(item):

                if item[i] != "00":
                    fullcollectionname.append(chr(int(item[i], base=16)))
                    i = i + 1
                else:
                    break
            fullcollectionname = "".join(fullcollectionname)

            documents = item[i + 9:]

            document_result = self.__parse_document(documents)
            # print "client2serverData:",document_result

            if document_result.get("mechanism", None) == "SCRAM-SHA-1":
                payload = document_result.get("payload")
                # like n,,n=tanjiti,r=MjAyNjgwMDMwMDcy
                r_index = payload.find(",r=")
                n_index = payload.find("n,,n=")
                user = payload[n_index + 5:r_index]
                passwd = payload[r_index + 3:]


            elif document_result.get("authenticate", 0) == 1:
                user = document_result.get("user", None)
                passwd = document_result.get("key", None)


            else:
                continue

            if user and passwd:
                crack_detail = "%s%s%s%s%s%s" % (sep, user, sep, passwd, sep, fullcollectionname)
                auth_detail.append(crack_detail)

        # print "auth_detail:",auth_detail
        return auth_detail

    def __parse_document(self, documents):
        """

        Args:
            documents:

        Returns:

        """
        # http://bsonspec.org/spec.html
        # https://cs.fit.edu/code/svn/cse2410f13team7/wireshark/epan/dissectors/packet-mongo.c
        # documentlength 4
        # elements
        # elements组成: type 1 + elementName 长度不固定,以00结尾 + [length] + value 长度由type决定

        result = OrderedDict()
        len_of_documents = len(documents)

        documents_length = self.__chrs2int(documents[0:4])
        if documents_length != len_of_documents:
            return

        i = 4

        while i < len_of_documents - 1:
            # element type
            element_type = documents[i]

            # element_name
            pos_00 = i + 1
            for j in range(pos_00, len_of_documents):

                if documents[j] == "00":
                    pos_00 = j
                    break

            element_name = "".join(chr(int(ch, base=16)) for ch in documents[i + 1:j])

            element_type_msg = MongoDBAuth.__DOCUMENT_DATA_TYPE.get(element_type)
            if element_type_msg == "boolean":

                element_value = documents[pos_00 + 1]
                next_i = pos_00 + 2
                i = next_i

            elif element_type_msg == "int32":
                element_value = self.__chrs2int(documents[pos_00 + 1:pos_00 + 1 + 4])
                next_i = pos_00 + 5
                i = next_i

            elif element_type_msg in ["datetime", "double", "int64"]:
                element_value = self.__chrs2int(documents[pos_00 + 1:pos_00 + 1 + 8])
                next_i = pos_00 + 9
                i = next_i

            elif element_type_msg in ["string", "binary"]:
                # get length
                element_length = self.__chrs2int(documents[pos_00 + 1:pos_00 + 1 + 4])

                if element_type_msg == "binary":
                    element_value = documents[pos_00 + 6:pos_00 + 6 + element_length]
                    element_value = "".join(chr(int(e, base=16)) for e in element_value)
                    next_i = pos_00 + 6 + element_length
                else:
                    element_value = documents[pos_00 + 5:pos_00 + 4 + element_length]
                    element_value = "".join(chr(int(e, base=16)) for e in element_value)
                    next_i = pos_00 + 5 + element_length

                i = next_i
            elif element_type_msg in ["document"]:
                element_length = self.__chrs2int(documents[pos_00 + 1:pos_00 + 1 + 4])
                element_value = "".join(documents[pos_00 + 5:pos_00 + 5 + element_length])
                next_i = pos_00 + 5 + element_length
                i = next_i

            else:
                element_value = ""
                logging.error("[UNSUPPORT_DOCUMENTTYPE]: %s" % element_type)

                break
            result[element_name] = element_value

        return result

    def __split_mongo_data(self, data):
        """
        splite packets-str to packet list
        :param data:
        :return:
        """
        mongo_data_list = []
        chrs = mills.str2hex(data, return_str=False)

        len_of_chrs = len(chrs)

        offset = 0

        while offset < len_of_chrs:
            # https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/
            # 协议格式:  前4个字节表示消息长度
            #  字节序采用：小端字节序

            try:

                len_of_message_chrs = chrs[offset:offset + 4]

                len_of_message = self.__chrs2int(len_of_message_chrs)

                next_offset = offset + len_of_message
                data_item = chrs[offset:next_offset]
                mongo_data_list.append(data_item)

                offset = next_offset


            except Exception as e:
                logging.error("[PACKET_LENGTH_COMPUTER_FAILED]: %r" % e)
                return mongo_data_list

        return mongo_data_list

    def __chrs2int(self, chrs):
        """

        Args:
            len_of_message_chrs:

        Returns:

        """
        len_of_message_str = "".join(reversed(chrs))
        len_of_message = int(len_of_message_str, base=16)
        return len_of_message


