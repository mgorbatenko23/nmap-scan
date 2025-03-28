import shutil
from typing import Optional

from nmap_scan.exceptions import NmapNotInstalledError


def get_nmap_path(path: Optional[str] = None) -> str:
    """ Get the path to the nmap scanner.

    Args:
        path: The path to look for the nmap scanner.

    Raises:
        NmapNotInstalledError: if the nmap scanner is not found.

    """
    nmap_path = shutil.which('nmap', path=path)
    if nmap_path is None:
        raise NmapNotInstalledError
    else:
        return nmap_path
