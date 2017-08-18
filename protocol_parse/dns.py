# -*- coding: utf-8 -*-
import logging
import sys

import dnslib

reload(sys)
sys.setdefaultencoding('utf8')

import lib.mills as mills

QTYPE = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
         16: 'TXT', 17: 'RP', 18: 'AFSDB', 24: 'SIG', 25: 'KEY', 28: 'AAAA',
         29: 'LOC', 33: 'SRV', 35: 'NAPTR', 36: 'KX', 37: 'CERT', 39: 'DNAME',
         41: 'OPT', 42: 'APL', 43: 'DS', 44: 'SSHFP', 45: 'IPSECKEY',
         46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 49: 'DHCID', 50: 'NSEC3',
         51: 'NSEC3PARAM', 52: 'TLSA', 55: 'HIP', 99: 'SPF', 249: 'TKEY',
         250: 'TSIG', 251: 'IXFR', 252: 'AXFR', 255: 'ANY', 257: 'TYPE257',
         32768: 'TA', 32769: 'DLV'}

CLASS = {1: 'IN', 2: 'CS', 3: 'CH', 4: 'Hesiod', 254: 'None', 255: '*'}

QR = {0: 'QUERY', 1: 'RESPONSE'}

RCODE = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
         4: 'NOTIMP', 5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET',
         8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE'}

OPCODE = {0: 'QUERY', 1: 'IQUERY', 2: 'STATUS', 5: 'UPDATE'}


class DNSHeader(object):
    """

    Args:
        object:

    Returns:

    """

    def __init__(self, id, qr, opcode, aa, tc, rd, ra, rcode,
                 num_of_questions,
                 num_of_answers,
                 num_of_authority,
                 num_of_additional):
        """

        Args:
            id: transaction id
            qr: query/response 0:query 1:response
            opcode:
            aa: authoritative
            tc: truncated
            rd: recursion desired
            ra:  recursion available
            rcode: reply code 0:noerror
            num_of_questions:
            num_of_answers:
            num_of_authority:
            num_of_additional:
        """
        self.id = id
        self.qr = qr
        self.opcode = OPCODE.get(opcode, opcode)
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.rcode = RCODE.get(rcode, rcode)
        self.num_of_questions = num_of_questions
        self.num_of_answers = num_of_answers
        self.num_of_authority = num_of_authority
        self.num_of_additional = num_of_additional

    def toDict(self):
        """
        object 2 dict
        :return:
        """
        return mills.classinstance2dict(self)


class DNSQuestion(object):
    """

    """

    def __init__(self, qname, qtype, qclass):
        """

        Args:
            qname:
            qtype:
            qclass:
        """
        self.qname = str(qname)
        self.qtype = QTYPE.get(qtype, qtype)
        self.qclass = CLASS.get(qclass, qclass)

    def toDict(self):
        """
        object 2 dict
        :return:
        """
        return mills.classinstance2dict(self)


class DNSRR(object):
    """
    Answers, Authority, Additonal
    """

    def __init__(self, rname=None, rtype=1, rclass=1, ttl=0, rdata=None):
        """

        Args:
            rname:
            rtype:
            rclass:
            ttl:
            rdata:
        """
        self.rname = str(rname)
        self.rtype = QTYPE.get(rtype, rtype)
        self.rclass = rclass  # CLASS.get(rclass, rclass)
        self.ttl = ttl
        self.rdata = str(rdata)

    def toDict(self):
        """
        object 2 dict
        :return:
        """
        return mills.classinstance2dict(self)


class DNSProtocol(object):
    """
    parse DNS protocol
    """

    def __init__(self,
                 data_tuple
                 ):
        """

        :param data_tuple:
        """
        (ts, src_ip, src_port, dst_ip, dst_port, data) = data_tuple
        self.data_tuple = data_tuple
        self.ts = ts

        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.data = data

    def parse_data(self, sep="\x00"):
        """

        :param sep:
        :return:
        """

        result = {}
        result["ts"] = self.ts
        result["src_ip"] = self.src_ip
        result["src_port"] = self.src_port
        result["dst_ip"] = self.dst_ip
        result["dst_port"] = self.dst_port
        try:

            packet = dnslib.DNSRecord.parse(self.data)
            header = packet.header

            header_ob = DNSHeader(header.id, header.qr, header.opcode,
                                  header.aa, header.tc, header.rd, header.ra, header.rcode,
                                  header.q, header.a, header.auth, header.ar)
            header_dict = header_ob.toDict()
            result["header"] = header_dict

            if header_ob.num_of_questions > 0:
                result["questions"] = list()
                questions = packet.questions
                for i in range(0, header_ob.num_of_questions):
                    q = questions[i]
                    q_ob = DNSQuestion(q.qname, q.qtype, q.qclass)
                    result["questions"].append(q_ob.toDict())
            if header_ob.num_of_answers > 0:
                result["answers"] = list()
                answers = packet.rr
                for i in range(0, header_ob.num_of_answers):
                    a = answers[i]

                    rr_ob = DNSRR(rname=a.rname, rtype=a.rtype,
                                  rclass=a.rtype, ttl=a.ttl,
                                  rdata=a.rdata)

                    result["answers"].append(rr_ob.toDict())

            if header_ob.num_of_authority > 0:
                auths = packet.auth
                for i in range(0, header_ob.num_of_authority):
                    result["authority"] = list()
                    auth = auths[i]
                    rr_ob = DNSRR(rname=auth.rname, rtype=auth.rtype,
                                  rclass=auth.rtype, ttl=auth.ttl,
                                  rdata=auth.rdata)
                    result["authority"].append(rr_ob.toDict())

            if header_ob.num_of_additional > 0:
                additionals = packet.ar
                for i in range(0, header_ob.num_of_additional):
                    result["additional"] = list()
                    additional = additionals[i]
                    rr_ob = DNSRR(rname=additional.rname, rtype=additional.rtype,
                                  rclass=additional.rtype, ttl=additional.ttl,
                                  rdata=additional.rdata)
                    result["additional"].append(rr_ob.toDict())

            yield result



        except Exception as e:
            logging.error("[DNS_PARSE_ERROR]: %r" % e)


if __name__ == "__main__":

    import lib.logger as logger
    import codecs
    import json

    logger.generate_special_logger(level=logging.INFO,
                                   logtype="dns_parse",
                                   curdir=mills.path("./log"))

    pcap_file = mills.path("data/tcpudpdata/dns.pcap/udp.txt")
    lines = []
    with codecs.open(pcap_file, mode='rb', encoding='utf-8') as fr:
        for line in fr:
            if line:
                lines.append(line)

    for i in range(0, len(lines)):
        pqa = DNSProtocol(eval(lines[i]))
        result = pqa.parse_data()

        for i in result:
            print json.dumps(i, indent=4)
