import abc
import csv
import ipaddress
import logging
from unicon.plugins.linux import LinuxConnection
from pprint import pformat as pf

logger = logging.getLogger()


class VirtualMachineHandler:

    def __init__(self, ip: str, credentials: dict):
        super(VirtualMachineHandler).__init__(ip, credentials)
        self.handler = None

