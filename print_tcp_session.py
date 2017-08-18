import logging

from lib.ServerConf import ServerConf
from stream_handler.StreamHandler import StreamHandler


def main():
    """

    :return:
    """
    co = ServerConf(mills.path("etc/server.yaml"))

    sho = StreamHandler(pcap_file=co.pcap_file,
                        device=co.device,
                        bpf_filter=co.bpf_filter,
                        dst_tcp_ip_filter=co.dst_tcp_ip_filter,
                        dst_tcp_port_filter=co.dst_tcp_port_filter,
                        src_tcp_ip_filter=co.src_tcp_ip_filter,
                        src_tcp_port_filter=co.src_tcp_port_filter,
                        udp_ip_filter=co.udp_ip_filter,
                        udp_port_filter=co.udp_port_filter,
                        data_level=co.data_level,
                        data_stream_direct=co.data_stream_direct,
                        std_output_enable=co.std_output_enable,
                        file_output_path=co.file_output_path,
                        protocol_parse_conf=co.protocol_parse_conf,
                        is_handle_ip=co.is_handle_ip,
                        is_handle_tcp=co.is_handle_tcp,
                        is_handle_udp=co.is_handle_udp,
                        sqlite3_output_enable=co.sqlite3_output_enable,
                        sqlite3_output_path=co.sqlite3_output_path,
                        sqlite3_output_schema=co.sqlite3_output_schema,
                        sqlite3_renew=co.sqlite3_renew)
    sho.run()


if __name__ == "__main__":
    """
    """
    import lib.mills as mills
    import lib.logger as logger

    logger.generate_special_logger(level=logging.DEBUG,
                                   logtype="tcpsession",
                                   curdir=mills.path("./log"),
                                   ismultiprocess=False)
    main()
