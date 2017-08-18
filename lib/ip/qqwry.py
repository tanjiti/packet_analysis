# -*- coding: utf-8 -*-
import logging
import os
import socket
from struct import unpack

import wget

import lib.mills as mills


class QQWry(object):
    'define QQWry ip-geo lookup tool'

    def __init__(self, file_name=None):
        self.source_name = "qqwry"
        self.qqwry_source_url = {
            'copywrite_url': 'http://update.cz88.net/ip/copywrite.rar',
            'data_url': 'http://update.cz88.net/ip/qqwry.rar',
        }

        self.qqwry_down_path = {
            'ip': mills.path("data/ipdb/qqwry.dat"),
            'copywrite_rar': mills.path("data/ipdb/copywrite.rar"),
            "qqwry_rar": mills.path("data/ipdb/qqwry.rar")

        }
        if not file_name:
            file_name = self.qqwry_down_path["ip"]

        if not os.path.exists(file_name):
            self.db_update()

        with open(file_name, 'r') as dbf:
            self.data = dbf.read()
            self.startindex, self.lastindex = unpack('II', self.data[:8])
            self.count = (self.lastindex - self.startindex) / 7 + 1

        self.ip_data_field = [
            'country',
            'isp'
        ]

    def db_update(self):
        '''更新 QQWry IP数据库

        参考：https://github.com/lilydjwg/winterpy/blob/master/pylib/QQWry.py
        '''
        import zlib

        def decipher_data(key, data):
            h = bytearray()
            for b in data[:0x200]:
                b = ord(b)
                key *= 0x805
                key += 1
                key &= 0xff
                h.append(key ^ b)
            return bytes(h) + data[0x200:]

        def unpack_meta(data):
            # http://microcai.org/2014/05/11/qqwry_dat_download.html
            (sign, version, _1, size, _, key, text,
             link) = unpack('<4sIIIII128s128s', data)
            sign = sign.decode('gb18030')
            text = text.rstrip(b'\x00').decode('gb18030')
            link = link.rstrip(b'\x00').decode('gb18030')
            del data
            return locals()

        # download copywrite.rar ,qqwry.rar and unrar qqwry.rar
        copywrite_url = self.qqwry_source_url["copywrite_url"]
        qqwry_url = self.qqwry_source_url["data_url"]
        copywrite_rar_path = self.qqwry_down_path["copywrite_rar"]
        qqwry_rar_path = self.qqwry_down_path["qqwry_rar"]

        if os.path.exists(copywrite_rar_path) and os.path.isfile(copywrite_rar_path):
            os.remove(copywrite_rar_path)
        try:
            wget.download(copywrite_url, copywrite_rar_path)
            d = open(copywrite_rar_path, 'rb').read()
            info = unpack_meta(d)
            if os.path.isfile(qqwry_rar_path):
                os.remove(qqwry_rar_path)
            try:
                wget.download(qqwry_url, qqwry_rar_path)
                d = open(qqwry_rar_path, 'rb').read()
                d = decipher_data(info['key'], d)
                d = zlib.decompress(d)
                open(self.qqwry_down_path["ip"], 'w').write(d)

                os.unlink(copywrite_rar_path)
                os.unlink(qqwry_rar_path)
            except Exception as e:
                content = "wget qqwry.rar %s failed: %s" % (qqwry_url, str(e))
                logging.error(content)

        except Exception as e:
            content = "wget copywrite.rar %s failed: %s" % (copywrite_url, str(e))
            logging.error(content)

    def _dichotomy(self, data, kwd, begin, end, index):
        """dichotomy search"""
        if end - begin <= 1:
            return begin

        half = (begin + end) / 2

        i = index + half * 7
        tmp = unpack('I', data[i: i + 4])[0]

        if kwd <= tmp:
            return self._dichotomy(data, kwd, begin, half, index)
        else:
            return self._dichotomy(data, kwd, half, end, index)

    def _getstring(self, offset):
        """get country / city string"""
        gb2312_str = self.data[offset: self.data.find('\0', offset)]
        try:
            utf8_str = gb2312_str.decode('gb2312')
        except:
            utf8_str = ""
        return utf8_str

    def _index(self, ip):
        """get ip index with ip offset"""
        return self.startindex + 7 * (
            self._dichotomy(self.data, unpack('!I', socket.inet_aton(ip))[0],
                            0, self.count - 1, self.startindex))

    def _record(self, offset):
        """a record = [IP Start] + [IP Offset]"""
        return unpack('I', "%s\0" % self.data[offset: offset + 3])[0]

    def _country_redirect(self, offset):
        """record redirect"""
        byte = ord(self.data[offset])

        if byte == 1 or byte == 2:
            return self._country_redirect(self._record(offset + 1))
        else:
            return self._getstring(offset)

    def _country_city(self, offset, ip=0):
        """get country / city from a record"""
        byte = ord(self.data[offset])

        if byte == 1:
            return self._country_city(self._record(offset + 1))

        elif byte == 2:
            return (self._country_redirect(self._record(offset + 1)),
                    self._country_redirect(offset + 4))
        else:
            return (self._getstring(offset),
                    self._country_redirect(self.data.find('\0', offset) + 1))

    def ip_lookup(self, ip="", isupdate=False):
        """get a single ip location"""
        if isupdate:
            self.db_update()

        result = self._country_city(
            self._record(self._index(ip) + 4) + 4)
        result = dict(zip(self.ip_data_field, result))
        result["ip"] = ip
        if result["isp"].lower().find("cz88.net"):
            result["isp"] = "NONE"
        return result
