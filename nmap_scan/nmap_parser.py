import xml.etree.ElementTree as ET
from collections import defaultdict
from ipaddress import IPv4Address
import typing as t

from nmap_scan.data import Host
from nmap_scan.exceptions import NmapXMLParserError, XMLElementNotFound


class NmapParser:
    """ Parsing nmap output. """

    def __init__(self, nmap_xml_output: bytes):
        self._nmap_xml_output = nmap_xml_output

    def run(self) -> None:
        """ Parse the XML output of the nmap scanner. """
        hosts = []
        for xml_et_host in self._get_xml_et_hosts():
            ip = self._get_ip_addr(xml_et_host)
            status = self._get_host_status(xml_et_host)
            hostnames = self._get_hostnames(xml_et_host)
            tcp_ports = self._get_ports(xml_et_host, 'tcp')
            udp_ports = self._get_ports(xml_et_host, 'udp')

            hosts.append(Host(ip=ip,
                              status=status,
                              hostnames=hostnames,
                              tcp_ports=tcp_ports,
                              udp_ports=udp_ports))

        self._hosts = self._sorted_hosts_by_ip(hosts)

    def get_hosts(self) -> list[Host]:
        """ Get a list of parsed hosts. """
        assert hasattr(self, '_hosts'), \
            'You must first call the method self.run()'

        return self._hosts

    def _find_xml_et(self, xml_et: ET.Element, match: str) -> ET.Element:
        _xml_et = xml_et.find(match)
        if _xml_et is not None:
            return _xml_et
        else:
            raise XMLElementNotFound

    def _get_xml_et_hosts(self) -> list[ET.Element]:
        """ Get a list of hosts in XML format. """
        try:
            root = ET.fromstring(self._nmap_xml_output)
        except ET.ParseError:
            raise NmapXMLParserError(f'Error parsing nmap output. '
                                     f'Check nmap parameters.')

        return root.findall('host')

    def _get_ip_addr(self, xml_et_host: ET.Element) -> str:
        """ Parse the XML host and return the IP address. """
        try:
            xml_et_address = self._find_xml_et(xml_et_host, 'address')
        except XMLElementNotFound:
            return ''
        else:
            return xml_et_address.get('addr', '')

    def _get_host_status(self, xml_et_host: ET.Element) -> str:
        """ Parse XML host and return host ip status (up/down). """
        try:
            xml_et_status = self._find_xml_et(xml_et_host, 'status')
        except XMLElementNotFound:
            return ''
        else:
            return xml_et_status.get('state', '')

    def _get_hostnames(self, xml_et_host: ET.Element) -> list[str]:
        """ Parse the XML host and return the hostname of the host. """
        hostnames = []
        for xml_et_hostname in xml_et_host.iter('hostname'):
            hostname = xml_et_hostname.get('name', '')
            hostnames.append(hostname)

        return hostnames

    def _get_ports(self,
                   xml_et_host: ET.Element,
                   protocol: t.Literal['tcp', 'udp']) -> defaultdict[str, list[int]]:
        """ Parse the XML host and return a dictionary of state
            ports and their numbers.
        """
        ports = defaultdict(list)
        for xml_et_port in xml_et_host.iter('port'):
            if xml_et_port.get('protocol') == protocol:
                portid = int(xml_et_port.get('portid', 0))
                try:
                    xml_et_state = self._find_xml_et(xml_et_port, 'state')
                except XMLElementNotFound:
                    continue
                else:
                    state = xml_et_state.get('state', '')
                    ports[state].append(portid)

        return ports

    def _sorted_hosts_by_ip(self, hosts: list[Host]) -> list[Host]:
        """ Sorting hosts by IP address. """
        return sorted(hosts, key=lambda host: IPv4Address(host.ip))
