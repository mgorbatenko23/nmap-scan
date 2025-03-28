from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class Host:
    """ Dataclass for recording scan results with the nmap scanner. """
    ip: str = ''
    status: str = ''
    hostnames: list[str] = field(default_factory=list[str])
    tcp_ports: defaultdict[str, list[int]] = field(default_factory=lambda: defaultdict(list))
    udp_ports: defaultdict[str, list[int]] = field(default_factory=lambda: defaultdict(list))
