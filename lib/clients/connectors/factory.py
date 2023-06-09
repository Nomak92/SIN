from lib.clients.connectors.base import BaseDeviceHandler
from lib.clients.connectors.imc import ImcDeviceHandler
from lib.clients.connectors.mds import MDSDeviceHandler
from lib.clients.connectors.ucsm import UcsmChassisDeviceHandler, UcsmServerDeviceHandler
from lib.clients.connectors.esxi import EsxiDeviceHandler
import logging
from typing import TypeVar

from lib.clients.connectors.vcenter import VcenterDeviceHandler

logger = logging.getLogger()

DeviceHandler = TypeVar('DeviceHandler', bound=BaseDeviceHandler)


class DeviceHandlerFactory:

    def __init__(self, platform: str, ip: str, credentials: dict):
        self.platform = platform
        self.ip = ip
        self.credentials = credentials

    def create(self) -> DeviceHandler:
        if self.platform.lower() == 'cimc':
            return ImcDeviceHandler(self.ip, self.credentials)
        elif self.platform.lower() == 'ucsm_chassis':
            return UcsmChassisDeviceHandler(self.ip, self.credentials)
        elif self.platform.lower() == 'ucsm_server':
            return UcsmServerDeviceHandler(self.ip, self.credentials)
        elif self.platform.lower() == 'esxi':
            return EsxiDeviceHandler(self.ip, self.credentials)
        elif self.platform.lower() == 'vcenter':
            return VcenterDeviceHandler(self.ip, self.credentials)
        elif self.platform.lower() == 'mds':
            return MDSDeviceHandler(self.ip, self.credentials)
        else:
            logger.error(f'No handler found for platform {self.platform}')
            raise NotImplementedError(f'No handler found for platform {self.platform}')
