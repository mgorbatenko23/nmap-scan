from unittest.mock import Mock, patch

from nmap_scan.data import Host
from nmap_scan.nmap_scan import Nmap  # type: ignore

from fixture import load_nmap_xml_output, expected_hosts


class TestNmap:
    @patch('nmap_scan.nmap_scan.get_nmap_path')
    def test__get_nmap_command(self, mock_get_nmap_path: Mock) -> None:
        mock_get_nmap_path.return_value = '/usr/bin/nmap'
        nmap = Nmap()
        nmap_cmd = nmap._get_nmap_command(['10.10.1.1'], '-v -n -sn')
        assert nmap_cmd == '/usr/bin/nmap -v -n -sn -oX - 10.10.1.1'

    @patch('nmap_scan.nmap_scan.get_nmap_path')
    def test_scan(self,
                  mock_get_nmap_path: Mock,
                  load_nmap_xml_output: bytes,
                  expected_hosts: list[Host]) -> None:
        mock_get_nmap_path.return_value = '/usr/bin/nmap'
        nmap = Nmap()
        nmap._run_nmap_command = Mock()
        nmap._run_nmap_command.return_value = load_nmap_xml_output
        nmap.scan(['10.10.1.4,32'], options='-v -sS -p22,23')

        assert nmap._scan_result == expected_hosts
