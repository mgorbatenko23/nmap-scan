from __future__ import annotations


import json
import shlex
import subprocess
import xmltodict
import typing as t

from nmap_scan.exceptions import NmapExecutionError
from nmap_scan.utils import get_nmap_path
from nmap_scan.data import Host
from nmap_scan.nmap_parser import NmapParser


class Nmap:
    """ Class used to scan the network.

        Example:
            >>> import nmap_scan
            >>> nmap = Nmap()
            >>> nmap.scan(['10.10.1.0/24'], '-n -sn -v')
            >>> nmap.get_scan_result_as_json()
                        or
            >>> nmap.get_scan_result()
    """

    def __init__(self, *, path: t.Optional[str] = None) -> None:
        self._nmap_tool = get_nmap_path(path)

    def scan(self,
             targets: list[str],
             options: str,
             timeout: t.Optional[int] = None) -> None:
        """ Perform a scan in accordance with the specified
            parameters of the nmap scanner.
        """
        self._cmd_line = self._get_nmap_command(targets, options)
        self._nmap_xml_output = self._run_nmap_command(self._cmd_line, timeout)
        nmap_parser = NmapParser(self._nmap_xml_output)
        nmap_parser.run()
        self._scan_result = nmap_parser.get_hosts()

    def get_raw_nmap_output_as_dict(self) -> dict[t.Any, t.Any]:
        """ Get output nmap scan as dict """
        assert hasattr(self, '_nmap_xml_output'), \
            'Do a scan before trying to get_nmap_output_dict'

        return xmltodict.parse(self._nmap_xml_output)

    def get_scan_result_as_dataclasses(self) -> list[Host]:
        """ Get the scan result as a list of the Host dataclass. """
        assert hasattr(self, '_scan_result'), \
            'Do a scan before trying to get_scan_result'

        return self._scan_result

    def get_scan_result_as_json(self) -> str:
        """ Get the scan result as json. """
        assert hasattr(self, '_scan_result'), \
            'Do a scan before trying to get_scan_result_as_json'
        hosts = []
        for host in self._scan_result:
            hosts.append({'ip': host.ip,
                          'status': host.status,
                          'hostnames': host.hostnames,
                          'tcp_ports': dict(host.tcp_ports),
                          'udp_ports': dict(host.udp_ports)
                          })

        return json.dumps(hosts)

    def get_cmd_line(self) -> str:
        """ Get information about the executed command. """
        assert hasattr(self, '_cmd_line'), \
            'Do a scan before trying to get_cmd_line'

        return self._cmd_line

    def _get_nmap_command(self, targets: list[str], options: str) -> str:
        """ Generate the nmap command. Includes the nmap scanner
            path and scanning parameters.
        """
        target = ' '.join([obj.strip() for obj in targets])

        return f'{self._nmap_tool} {options} -oX - {target}'

    def _run_nmap_command(self,
                          cmd: str,
                          timeout: t.Optional[int] = None) -> bytes:
        """ Run nmap scanner to scan hosts. """
        args = shlex.split(cmd, posix=False)

        sub_proc = subprocess.Popen(args,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

        try:
            nmap_xml_output, _ = sub_proc.communicate(timeout=timeout)
        except subprocess.SubprocessError:
            sub_proc.kill()
            raise NmapExecutionError

        return nmap_xml_output
