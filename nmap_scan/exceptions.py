class NmapNotInstalledError(Exception):
    """ Exception raised when nmap is not installed """


class NmapExecutionError(Exception):
    """ Exception raised when en error occurred during nmap call """


class NmapXMLParserError(Exception):
    """ Exception raised when we can't parse the output """


class XMLElementNotFound(Exception):
    """ Exception raised when xml element can`t found """
