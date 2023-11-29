import abc
from typing import Callable
from pynetbox.core.response import Record
from lib.clients.base import BasePlatformClient
from lib.clients.connectors.vcenter import VcenterVirtualMachineHandler
from lib.clients.netbox import NetboxClient
from lib.models.validators import NetboxVirtualMachine
from lib.utils.lookup import combine_dict_values
import logging
from pprint import pformat as pf

logger = logging.getLogger()


class VMPlatformClient(BasePlatformClient, abc.ABC):
    management_handler: VcenterVirtualMachineHandler
    os_handler: None

    def __init__(self, imported_data: dict, password_handler: Callable[[str], str] = None):
        super().__init__(imported_data, password_handler=password_handler)
        assert self.platform.lower() == 'vm', f'Platform {self.platform} is not supported by Virtual Machine client'

    def _validate(self, data: dict) -> NetboxVirtualMachine:
        logger.debug(f'Starting validation of device {data["name"]}')
        return NetboxVirtualMachine(**data)

    def discover(self) -> bool:
        """
            Discover the Virtual Machine in vCenter
            :return: True if discovered successfully, False otherwise
        """
        results = {
            "name": self.imported_data["name"],
            "status": self.imported_data.get("status", "active"),
            "site": self.imported_data.get('site', None),
            "cluster": self.imported_data.get('cluster', None),
            "device": self.imported_data.get('device', None),
            "role": self.imported_data.get('device_role', None),
            "tenant": self.imported_data.get('tenant', None),
            "platform": self.imported_data.get('platform', None),
            "primary_ip4": self.imported_data.get('primary_ip4', None),
            "primary_ip6": self.imported_data.get('primary_ip6', None),
            "vcpus": self.imported_data.get('vcpus', None),
            "memory": self.imported_data.get('memory', None),
            "disk": self.imported_data.get('disk', None),
            "description": self.imported_data.get('description', ""),
            "comments": self.imported_data.get('comments', ""),
            "tags": self.imported_data.get('tags', []),
            "custom_fields": self.imported_data.get('custom_fields', None)
        }
        results = combine_dict_values(results, self.management_handler.discover_vm(self.imported_data["name"]))
        if results:
            logger.debug(f'discovered_data = {pf(results)}')
            self.discovered_data = results
            return True
        else:
            return False

    def is_valid(self) -> bool:
        validator = self._validate(self.discovered_data)
        self.validated_data = validator.model_dump()
        logger.debug(f'validated_data = {pf(self.validated_data)}')
        return True if self.validated_data else False

    def push(self, netbox_client: NetboxClient) -> list[Record]:
        if not self.validated_data:
            raise ValueError('No validated data to push')
        logger.debug(f'Pushing Virtual Machine {self.validated_data["name"]} to Netbox')
        results = []
        primary_ip4 = self.validated_data.pop('primary_ip4', None)
        logger.debug(f'Pushing data to Netbox: {pf(self.validated_data)}')
        vm = netbox_client.create_or_update_vm(**self.validated_data)
        if vm is None:
            raise ValueError(f'Failed to create or update device {self.validated_data["name"]}')
        results.append(vm)
        if self.validated_data.get('interfaces'):
            results.extend(netbox_client.add_virtual_interfaces(vm=vm.id,
                                                                interfaces=self.validated_data['interfaces']))
        if self.validated_data.get('ip_addresses'):
            results.extend(netbox_client.add_ip_addresses(device=vm.id,
                                                          ip_addresses=self.validated_data['ip_addresses']))
        if primary_ip4 is not None:
            logger.info(f'Checking if VM {vm.name} has primary IP {primary_ip4}')
            if not vm.primary_ip4 or vm.primary_ip4.id != primary_ip4:
                logger.info(f'Checking if ip address {primary_ip4} already is assigned to another object')
                ip_assigned = netbox_client.get_assigned_ip_address(primary_ip4)
                if not ip_assigned or ip_assigned.virtual_machine.name == vm.name:
                    logger.info(f'Setting VM {vm.name} primary IP to {primary_ip4}')
                    vm.primary_ip4 = primary_ip4
                    vm.save()
                    logger.debug(f'Set device {vm.name} primary IP to {primary_ip4}')
                else:
                    logger.warning(f'IP address {primary_ip4} is already assigned to another object: '
                                   f'{ip_assigned.virtual_machine.name}')
            else:
                logger.info(f'Device {vm.name} already has primary IP {primary_ip4}')
        return results

