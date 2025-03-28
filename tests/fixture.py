import pytest
from collections import defaultdict

from nmap_scan.data import Host


@pytest.fixture
def load_nmap_xml_output() -> bytes:
    """ The result of executing the command
        nmap -v -sS -p22,23 -oX is 10.10.1.4,32. Output in XML format.
        XML for tests. Show only XML element `host`

        ....

        <host>
            <status state="down" reason="no-response" reason_ttl="0"/>
            <address addr="10.10.1.4" addrtype="ipv4"/>
        </host>
        <host starttime="1738527928" endtime="1738527928">
            <status state="up" reason="echo-reply" reason_ttl="63"/>
            <address addr="10.10.1.32" addrtype="ipv4"/>
            <hostnames>
                <hostname name="dhcp-01.example.com" type="PTR"/>
            </hostnames>
            <ports>
                <port protocol="tcp" portid="22">
                    <state state="open" reason="syn-ack" reason_ttl="63"/>
                    <service name="ssh" method="table" conf="3"/>
                </port>
                <port protocol="tcp" portid="23">
                    <state state="closed" reason="reset" reason_ttl="63"/>
                    <service name="telnet" method="table" conf="3"/>
                </port>
            </ports>
        </host>

        ...
    """
    with open('nmap_xml_output', 'br') as f_nmap_xml_output:
        nmap_xml_output = f_nmap_xml_output.read()

    return nmap_xml_output


@pytest.fixture
def expected_hosts() -> list[Host]:
    expected_hosts = [Host(ip='10.10.1.4', status='down'),
                      Host(ip='10.10.1.32',
                           status='up',
                           hostnames=['dhcp-01.example.com'],
                           tcp_ports=defaultdict(list, {'open': [22], 'closed': [23]}))
                      ]

    return expected_hosts
