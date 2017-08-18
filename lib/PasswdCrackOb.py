# -*- coding: utf-8 -*-
import mills


class PassWdCrackOb(object):
    """
    密码破解数据对象
    """

    def __init__(self,
                 service="",
                 src_ip="", src_port=0,
                 dst_ip="", dst_port=0,
                 crack_result=-1,
                 crack_detail="",
                 ts_start=0.0, ts_end=0.0,
                 ts_duration=0.0
                 ):
        """
        :param service: 协议服务，例如mysql
        :param src_ip: 源ip地址
        :param src_port: 源port地址
        :param dst_ip: 目的ip地址
        :param dst_port: 目的port地址
        :param crack_result:
        1： 成功
        2： 失败
        3： 未知错误
        :param crack_detail:
        :param ts_start: 开始时间
        :param ts_end: 结束时间
        :param protocolconf: 协议配置
        """
        self.service = service
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.crack_result = crack_result
        self.crack_detail = crack_detail

        self.ts_start = ts_start
        self.ts_end = ts_end

        if ts_duration == 0.0:
            self.ts_duration = self.ts_end - self.ts_start

    def toDict(self):
        """
        class instance object 2 dict
        :return:
        """
        return mills.classinstance2dict(self)
