import logging
from typing import Callable

from lib.clients.base import BasePlatformClient
from lib.clients.imc import ImcPlatformClient
from lib.clients.mds import MDSPlatformClient
from lib.clients.ucsm import UcsmChassisPlatformClient, UcsmServerPlatformClient
from lib.clients.vm import VMPlatformClient

logger = logging.getLogger()


def create_device_client(device_data: dict, password_handler: Callable[[str], str] = None) -> BasePlatformClient:
    """
    Create a device client based on the platform
    :param dict device_data: Device data to create the client
    :param password_handler:  Callable to get the password for the device, if password is not in plain text
    :return:
    """
    logger.debug(f'Creating device client for {device_data["name"]} with platform {device_data["platform"]}')
    if device_data['platform'].lower() == 'cimc':
        return ImcPlatformClient(device_data, password_handler=password_handler)
    elif device_data['platform'].lower() == 'ucsm_chassis':
        return UcsmChassisPlatformClient(device_data, password_handler=password_handler)
    elif device_data['platform'].lower() == 'ucsm_server':
        return UcsmServerPlatformClient(device_data, password_handler=password_handler)
    elif device_data['platform'].lower() == 'mds':
        return MDSPlatformClient(device_data, password_handler=password_handler)
    elif device_data['platform'].lower() == 'vm':
        return VMPlatformClient(device_data, password_handler=password_handler)
    else:
        logger.error(f'No client found for platform {device_data["platform"]}')
        raise NotImplementedError(f'No client found for platform {device_data["platform"]}')
