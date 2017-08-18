# -*- coding: utf-8 -*-

from qqwry import QQWry


def ip_lookup(ip, isupdate=False):
    """
    ip lookup
    :param ip:
    :param isonline:
    :return:
    """

    result = ip_lookup_offline(ip, isupdate=isupdate, source="qqwry")

    try:
        result = "%s-%s-%s-%s" % (result.get("country"),
                                  result.get("province"),
                                  result.get("city"),
                                  result.get("isp"))
    except:
        result = None
    return result


def ip_lookup_offline(ip="", isupdate=False, source="qqwry"):
    """
    query ip geo offline
    :param ip:
    :param isupdate:
    :param source:
    :return:
    """


    if source == "qqwry":
        qqwry_obj = QQWry()

        result = qqwry_obj.ip_lookup(ip=ip, isupdate=isupdate)
        return result


if __name__ == "__main__":
    import logging
    import lib.mills as mills
    import lib.logger as logger

    logger.generate_special_logger(level=logging.INFO,
                                   logtype="ipgeolookup",
                                   curdir=mills.path("./log"),
                                   ismultiprocess=False)
    ip = "103.20.248.10"
    print ip_lookup(ip,isupdate=True)
