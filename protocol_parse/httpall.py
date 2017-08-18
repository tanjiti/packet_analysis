# -*- coding: utf-8 -*-
import gzip
import logging
import sys
from StringIO import StringIO

import dpkt
import lib.mills as mills

reload(sys)
sys.setdefaultencoding('utf8')


class HTTPProtocol(object):
    """
    parse http protocol
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

    def parse_data(self, sep="\x00"):
        """

        :param sep:
        :return:
        """

        req = self.__parse_client_data()
        resp = self.__parse_server_data()
        # header
        """
        meta = "[{ts_start}-{ts_end}] {src_ip}:{src_port}--->{dst_ip}:{dst_port}".format(
            src_ip=self.src_ip,
            src_port=self.src_port,
            dst_ip=self.dst_ip,
            dst_port=self.dst_port,
            ts_start=self.ts_start,
            ts_end=self.ts_end
        )

        result = "{meta}{sep}{req}{sep}{resp}".format(
            meta=meta,
            sep=os.linesep,
            req=req,
            resp=resp
        )
        return result
        """
        result = {}
        result["ts_start"] = self.ts_start
        result["ts_end"] = self.ts_end
        result["src_ip"] = self.src_ip
        result["src_port"] = self.src_port
        result["dst_ip"] = self.dst_ip
        result["dst_port"] = self.dst_port
        result["req_method"] = req.method
        result["req_uri"] = req.uri
        result["req_version"] = req.version
        result["req_headers"] = req.headers
        result["req_body"] = req.body
        result["resp_status"] = resp.status
        result["resp_reason"] = resp.reason
        result["resp_version"] = resp.version
        result["resp_headers"] = resp.headers
        result["resp_body"] = resp.body
        yield result

    def __parse_server_data(self):
        """

        :return:
        """
        if self.data_s2c:
            try:
                resp = dpkt.http.Response(self.data_s2c)
                if resp.headers.get("content-encoding") == "gzip":
                    data = resp.body
                    data_arrays = mills.str2hex(data)
                    if data_arrays[0:3] == ["1f", "8b", "08"]:
                        data_unzip = gzip.GzipFile(fileobj=StringIO(data)).read()

                        resp.body = data_unzip

                return resp
            except Exception as e:
                logging.error("[dpkt_http_resp_parse_failed]: %s %r" % (self.data_s2c, e))

    def __parse_client_data(self):
        """

        Returns:

        """
        if self.data_c2s:
            try:
                req = dpkt.http.Request(self.data_c2s)
                return req
            except Exception as e:
                logging.error("[dpkt_http_req_parse_failed]: %s %r" % (self.data_c2s, e))



