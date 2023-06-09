import abc
from pprint import pformat as pf
from concurrent.futures import as_completed, ThreadPoolExecutor
from typing import Callable

from pynetbox.core.response import Record

from lib.clients.base import BasePlatformClient
from lib.clients.connectors.esxi import EsxiDeviceHandler
from lib.clients.connectors.imc import ImcDeviceHandler
from lib.clients.netbox import NetboxClient
from lib.models.validators import NetboxDevice
from lib.utils.lookup import combine_dict_values
import logging

logger = logging.getLogger()


class ImcPlatformClient(BasePlatformClient, abc.ABC):
    management_handler: ImcDeviceHandler
    os_handler: EsxiDeviceHandler | None

    def __init__(self, imported_data: dict, password_handler: Callable[[str], str] = None):
        super().__init__(imported_data, password_handler=password_handler)
        assert self.platform.lower() == 'cimc', f'Platform {self.platform} is not supported by CIMC client'

    def _validate(self, data: dict) -> NetboxDevice:
        logger.debug(f'Starting validation of device {data["name"]}')
        return NetboxDevice(**data)

    def discover(self):
        results = {
            "airflow": self.imported_data.get('airflow', None),
            "asset_tag": self.imported_data.get('asset_tag', None),
            "cluster": self.imported_data.get('cluster', None),
            "comments": self.imported_data.get('comments', None),
            "custom_fields": self.imported_data.get('custom_fields', {
                "management_ip": self.management_ip,
                "management_username": self.management_username,
                "management_password": self.management_password,
                "os_ip": self.os_ip,
                "os_username": self.os_username,
                "os_password": self.os_password,
            }) if self.os_handler else self.imported_data.get('custom_fields', {
                "management_ip": self.management_ip,
                "management_username": self.management_username,
                "management_password": self.management_password
            }),
            "device_role": self.imported_data.get('device_role', None),
            "device_type": self.imported_data.get('device_type', None),
            "face": self.imported_data.get('face', None),
            "interfaces": self.imported_data.get('interfaces', None),
            "inventory_items": self.imported_data.get('inventory_items', None),
            "ip_addresses": self.imported_data.get('ip_addresses', None),
            "local_context_data": self.imported_data.get('local_context_data', None),
            "location": self.imported_data.get('location', None),
            "modules": self.imported_data.get('modules', None),
            "name": self.imported_data.get('name', None),
            "platform": self.imported_data.get('platform', None),
            "position": self.imported_data.get('position', None),
            "primary_ip4": self.imported_data.get('primary_ip4', None),
            "primary_ip6": self.imported_data.get('primary_ip6', None),
            "rack": self.imported_data.get('rack', None),
            "serial": self.imported_data.get('serial', None),
            "site": self.imported_data.get('site', None),
            "status": self.imported_data.get('status', None),
            "tags": self.imported_data.get('tags', None),
            "tenant": self.imported_data.get('tenant', None),
            "virtual_chassis": self.imported_data.get('virtual_chassis', None),
            "vc_position": self.imported_data.get('vc_position', None),
            "vc_priority": self.imported_data.get('vc_priority', None),
        }
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(self.management_handler.discover)]
            if self.os_handler:
                futures.append(executor.submit(self.os_handler.discover))
            for future in as_completed(futures):
                results = combine_dict_values(results, future.result())
        if results:
            logger.debug(f'discovered_data = {pf(results)}')
            self.discovered_data = results
            return True
        else:
            return False

    def is_valid(self) -> bool:
        validator = self._validate(self.discovered_data)
        self.validated_data = validator.dict()
        logger.debug(f'validated_data = {pf(self.validated_data)}')
        return True if self.validated_data else False

    def push(self, netbox_client: NetboxClient) -> list[Record]:
        if not self.validated_data:
            raise ValueError('No validated data to push')
        logger.debug(f'Pushing device {self.validated_data["name"]} to Netbox')
        results = []
        primary_ip4 = self.validated_data.pop('primary_ip4', None)
        logger.debug(f'Pushing data to Netbox: {pf(self.validated_data)}')
        device = netbox_client.create_or_update_device(**self.validated_data)
        if device is None:
            raise ValueError(f'Failed to create or update device {self.validated_data["name"]}')
        results.append(device)
        if self.validated_data.get('interfaces'):
            results.extend(netbox_client.add_interfaces(device=device.id, interfaces=self.validated_data['interfaces']))
        if self.validated_data.get('ip_addresses'):
            results.extend(netbox_client.add_ip_addresses(device=device.id,
                                                          ip_addresses=self.validated_data['ip_addresses']))
        if self.validated_data.get('modules'):
            results.extend(netbox_client.add_modules(device=device.id, modules=self.validated_data['modules']))
        if self.validated_data.get('inventory_items'):
            results.extend(netbox_client.add_inventory_items(device=device.id,
                                                             inventory_items=self.validated_data['inventory_items']))
        if primary_ip4 is not None:
            logger.info(f'Checking if device {device.name} has primary IP {primary_ip4}')
            if not device.primary_ip4 or device.primary_ip4.address != primary_ip4:
                logger.info(f'Checking if ip address {primary_ip4} already is assigned to another device')
                ip_assigned = netbox_client.get_assigned_ip_address(primary_ip4)
                if not ip_assigned or ip_assigned.device.name == device.name:
                    logger.info(f'Setting device {device.name} primary IP to {primary_ip4}')
                    device.primary_ip4 = primary_ip4
                    device.save()
                    logger.debug(f'Set device {device.name} primary IP to {primary_ip4}')
                else:
                    logger.warning(f'IP address {primary_ip4} is already assigned to another device: '
                                   f'{ip_assigned.device.name}')
            else:
                logger.info(f'Device {device.name} already has primary IP {primary_ip4}')
        return results
