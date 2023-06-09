import abc
from typing import Callable

from pynetbox.core.response import Record

from lib.clients.connectors.factory import DeviceHandlerFactory
from lib.clients.netbox import NetboxClient


class BasePlatformClient(abc.ABC):

    def __init__(self, imported_data: dict, password_handler: Callable[[str], str] = None):
        self.imported_data = imported_data
        self.discovered_data = None
        self.platform = self.imported_data['platform']  # Required
        self.os = self.imported_data.get('os', None)  # Optional
        self.management_ip = self.imported_data['management_ip']  # Required
        self.management_username = self.imported_data.get('management_username', None)  # Optional
        self.os_ip = self.imported_data.get('os_ip', None)  # Optional
        self.os_username = self.imported_data.get('os_username', None)  # Optional
        self.password_handler = password_handler  # Optional
        self.management_password = self.imported_data.get('management_password', None)  # Optional
        self.os_password = self.imported_data.get('os_password', None)  # Optional
        # formatted credentials for use with Unicon connection handlers
        self.management_credentials = {
            "default": {
                "username": self.management_username,
                "password": self.password_handler(self.management_password) if self.password_handler else
                self.management_password,
            }
        }
        # formatted credentials for use with Unicon connection handlers
        if self.os_username and self.os_password:
            self.os_credentials = {
                "default": {
                    "username": self.os_username,
                    "password": self.password_handler(self.os_password) if self.password_handler else self.os_password,
                }
            }
        else:
            self.os_credentials = None
        self.validated_data = None
        self.management_handler = DeviceHandlerFactory(self.platform, self.management_ip,
                                                       self.management_credentials).create()
        if self.os and self.os_ip:
            self.os_handler = DeviceHandlerFactory(self.os, self.os_ip, self.os_credentials).create()
        else:
            self.os_handler = None

    @abc.abstractmethod
    def _validate(self, data: dict) -> bool:
        pass

    @abc.abstractmethod
    def discover(self) -> bool:
        pass

    @abc.abstractmethod
    def is_valid(self) -> bool:
        pass

    @abc.abstractmethod
    def push(self, netbox_client: NetboxClient) -> list[Record]:
        pass
