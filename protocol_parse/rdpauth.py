# -*- coding: utf-8 -*-
# hydra -t 1 -W 1 -l apple -p pear -V  rdp://xxx.xxx.xxx.xxx
# hydra -t 1 -W 1 -L user.txt -P passwd.txt -V rdp://xxx.xxx.xxx.xxx
# https://wiki.wireshark.org/RDP
import re

from lib.PasswdCrackOb import PassWdCrackOb


class RDPAuth(object):
    """
    parse RDP auth protocol
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
        if not self.data_c2s:
            # only check the data_c2s
            return

        auth_detail = self.__parse_client_data()

        auth_detail.reverse()

        if auth_detail:

            while auth_detail:
                timetag = "%s-%s" % (self.ts_start, self.ts_end)
                crack_detail = "%s%s%s%s" % (sep, auth_detail.pop(), sep, timetag)

                pcci = PassWdCrackOb(service="rdp",
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
            # logging.error("[RDP_ODD_DATA]: %s" % repr(self.data_tuple))
            pass

    def __parse_server_data(self):
        """

        :return:
        """

        pass

    def __parse_client_data(self):
        """

        :return:
        """

        auth_detail = []
        parts = self.data_c2s.split("\r\n")

        client_data_parttern = re.compile(r'Cookie:\s+(\S+)')

        for p in parts:

            m = re.search(client_data_parttern, p)

            if m is not None:
                k = m.groups()[0]
                username = self.__parse_cookie(k)
                auth_detail.append(username)

        return auth_detail

    def __parse_cookie(self, st):
        user_pattern = re.compile(r'^mstshash=(\S+)$')
        ip_pattern = re.compile(r'^msts=(\d+)\.(\d+)\.(\d+)$')
        m = re.match(user_pattern, st)

        if m is not None:
            (user,) = m.groups()
            return user

        m = re.match(ip_pattern, st)
        if m is not None:
            (ip, port, _) = m.groups()

            port_str = hex(int(port))[2:]

            ports = self.reverse_str(port_str)
            ports_str = "".join(ports)
            port = int(ports_str, base=16)

            ip_str = hex(int(ip))[2:]
            len_of_ip_str = len(ip_str)

            if len_of_ip_str == 8:
                ips = [str(int(item, base=16)) for item in self.reverse_str(ip_str)]
                ip = ".".join(ips)

            return "%s:%s" % (ip, port)

    @staticmethod
    def reverse_str(st):
        """
        change 190c790a to ["0a","79","0c","19"]
        Returns:

        """
        len_of_str = len(st)
        if len_of_str % 2 == 0:
            parts = []
            for i in range(0, len_of_str, 2):
                parts.append(st[i] + st[i + 1])
            parts.reverse()
            return parts
