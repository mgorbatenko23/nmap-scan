from unittest.mock import Mock

from nmap_scan.data import Host
from nmap_scan.nmap_scan import NmapParser  # type: ignore
from fixture import load_nmap_xml_output, expected_hosts


class TestNmapParser:
    def test__get_ip_addr(self, load_nmap_xml_output: bytes) -> None:
        nmap_parser = NmapParser(load_nmap_xml_output)
        first_host_as_xml_et = nmap_parser._get_xml_et_hosts()[0]
        second_host_as_xml_et = nmap_parser._get_xml_et_hosts()[1]

        assert nmap_parser._get_ip_addr(first_host_as_xml_et) == '10.10.1.4'
        assert nmap_parser._get_ip_addr(second_host_as_xml_et) == '10.10.1.32'

    def test__get_host_status(self, load_nmap_xml_output: bytes) -> None:
        nmap_parser = NmapParser(load_nmap_xml_output)
        first_host_as_xml_et = nmap_parser._get_xml_et_hosts()[0]
        second_host_as_xml_et = nmap_parser._get_xml_et_hosts()[1]

        assert nmap_parser._get_host_status(first_host_as_xml_et) == 'down'
        assert nmap_parser._get_host_status(second_host_as_xml_et) == 'up'

    def test__get_hostnames(self, load_nmap_xml_output: bytes) -> None:
        nmap_parser = NmapParser(load_nmap_xml_output)
        first_host_as_xml_et = nmap_parser._get_xml_et_hosts()[0]
        second_host_as_xml_et = nmap_parser._get_xml_et_hosts()[1]

        assert nmap_parser._get_hostnames(first_host_as_xml_et) == []
        assert nmap_parser._get_hostnames(second_host_as_xml_et) == ['dhcp-01.example.com']

    def test__get_ports(self, load_nmap_xml_output: bytes) -> None:
        nmap_parser = NmapParser(load_nmap_xml_output)
        first_host_as_xml_et = nmap_parser._get_xml_et_hosts()[0]
        second_host_as_xml_et = nmap_parser._get_xml_et_hosts()[1]

        assert nmap_parser._get_ports(first_host_as_xml_et, 'tcp') == {}
        assert nmap_parser._get_ports(first_host_as_xml_et, 'udp') == {}

        assert nmap_parser._get_ports(second_host_as_xml_et, 'tcp') == {'open': [22],
                                                                        'closed': [23]
                                                                        }
        assert nmap_parser._get_ports(second_host_as_xml_et, 'udp') == {}

    def test_run(self,
                 load_nmap_xml_output: bytes,
                 expected_hosts: list[Host]) -> None:
        nmap_parser = NmapParser(load_nmap_xml_output)
        nmap_parser.run()

        assert nmap_parser._hosts == expected_hosts

    def test__sorted_hosts_by_ip(self) -> None:
        nmap_parser = NmapParser(Mock())
        hosts = [Host(ip='10.10.1.5', status='up'),
                 Host(ip='10.10.2.1', status='up'),
                 Host(ip='10.10.1.1', status='up'),
                 ]
        sorted_hosts = nmap_parser._sorted_hosts_by_ip(hosts)

        assert sorted_hosts[0].ip == '10.10.1.1'
        assert sorted_hosts[1].ip == '10.10.1.5'
        assert sorted_hosts[2].ip == '10.10.2.1'
