# -*- coding: utf-8 -*-
import codecs
import logging
import os
import re

import lib.mills as mills


class PortServiceMap(object):
    """
    根据端口与协议查找对应的服务
    """

    def __init__(self, servicefile=None):
        """

        :param servicefile:
        """
        if not servicefile:
            servicefile = mills.path("etc/nmap-services")

        self.servicefile = servicefile

        self.portservicedict = dict()

        if os.path.exists(servicefile):

            with codecs.open(servicefile, encoding='utf-8', mode='rb') as fr:
                for line in fr:
                    line = line.strip()
                    if line.startswith("#"):
                        continue

                    parts = re.split(r'\s+', line)

                    if len(parts) >= 2:
                        self.portservicedict[parts[1]] = parts[0]

        else:
            logging.error("[FILENOTEXITS]: %s" % servicefile)

    def lookup(self, port, protocol="tcp"):
        """

        :param port:
        :param protocol:
        :return:
        """
        key = "%d/%s" % (port, protocol)

        return self.portservicedict.get(key, "NONE")


if __name__ == "__main__":
    o = PortServiceMap()

    print o.lookup(6379)
