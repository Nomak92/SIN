import abc
from typing import Callable
from pynetbox.core.response import Record
from lib.clients.base import BasePlatformClient
from lib.clients.connectors.ucsm import UcsmChassisDeviceHandler, UcsmServerDeviceHandler
from lib.clients.connectors.vcenter import VcenterDeviceHandler
from lib.clients.netbox import NetboxClient
from lib.models.validators import NetboxVirtualChassis, NetboxDevice
from lib.utils.lookup import combine_dict_values
import logging
from pprint import pformat as pf

logger = logging.getLogger()


class UcsmChassisPlatformClient(BasePlatformClient, abc.ABC):
    management_handler: UcsmChassisDeviceHandler
    os_handler: VcenterDeviceHandler

    def __init__(self, imported_data: dict, password_handler: Callable[[str], str] = None):
        super().__init__(imported_data, password_handler=password_handler)
        assert self.platform.lower() == 'ucsm_chassis', f'Platform {self.platform} is not supported by UCSM Chassis ' \
                                                        f'client'

    def _validate(self, data: dict) -> NetboxVirtualChassis:
        logger.debug(f'Starting validation of Virtual Chassis {data["name"]}')
        return NetboxVirtualChassis(**data)

    def discover(self) -> bool:
        """
        Discover UCSM servers and compile into discovered_data
        :return:
        """
        results = self.management_handler.discover()
        # Set variables from imported data
        for chassis in results['members']:
            chassis['device_bays'] = []
            chassis['rack'] = self.imported_data.get('rack', None)
            chassis['site'] = self.imported_data.get('site', None)
            chassis['tenant'] = self.imported_data.get('tenant', None)
            chassis['platform'] = self.imported_data.get('platform', None)
            chassis['cluster'] = self.imported_data.get('cluster', None)
            chassis['local_context_data'] = self.imported_data.get('local_context_data', None)
            chassis['custom_fields'] = combine_dict_values(chassis.get('custom_fields', {}), {
                "management_ip": self.management_ip,
                "management_username": self.management_username,
                "management_password": self.management_password,
                "os_ip": self.os_ip,
                "os_username": self.os_username,
                "os_password": self.os_password,
            })
            chassis['comments'] = self.imported_data.get('comments', None)
            chassis['tags'] = self.imported_data.get('tags', None)
            chassis['asset_tag'] = self.imported_data.get('asset_tag', None)
            chassis['position'] = self.imported_data.get('position', None)
            chassis['face'] = self.imported_data.get('face', None)
            chassis['airflow'] = self.imported_data.get('airflow', None)
            chassis['location'] = self.imported_data.get('location', None)
            chassis["status"] = 'active'
            for device in chassis["devices"]:
                device['site'] = self.imported_data.get('site', None)
                device['rack'] = self.imported_data.get('rack', None)
                device['tenant'] = self.imported_data.get('tenant', None)
                device['platform'] = self.imported_data.get('platform', None)
                device['cluster'] = self.imported_data.get('cluster', None)
                device['local_context_data'] = self.imported_data.get('local_context_data', None)
                device['custom_fields'] = combine_dict_values(device.get('custom_fields', {}), {
                    'os_username': self.imported_data.get('blade_os_username', self.os_username),
                    'os_password': self.imported_data.get('blade_os_password', self.os_password),
                    'os_ip': self.os_ip,
                    'management_ip': self.management_ip,
                    'management_username': self.management_username,
                    'management_password': self.management_password,
                })
                device['comments'] = self.imported_data.get('comments', None)
                device['tags'] = self.imported_data.get('tags', None)
                device['asset_tag'] = self.imported_data.get('asset_tag', None)
                device['face'] = self.imported_data.get('face', None)
                device['airflow'] = self.imported_data.get('airflow', None)
                device['location'] = self.imported_data.get('location', None)
                device["status"] = 'active'
        if self.os_handler:
            for chassis in results['members']:
                for device in chassis['devices']:
                    os_results = self.os_handler.discover_host(device['serial'])
                    if not os_results:
                        logger.error(f'Could not discover OS data for {device["serial"]}')
                        raise ValueError(f'Could not discover OS data for {device["serial"]}')
                    device['custom_fields']['os_ip'] = os_results['os_ip']
                    device['name'] = os_results['name']
                    device["primary_ip4"] = os_results['primary_ip4']
                    device['interfaces'] = os_results['interfaces']
                    device['ip_addresses'] = os_results['ip_addresses']
        self.discovered_data = results
        logger.info(f'Discovered UCSM data for {results["name"]}:\n{pf(self.discovered_data)}')
        return True if self.discovered_data else False

    def is_valid(self) -> bool:
        validator = self._validate(self.discovered_data)
        self.validated_data = validator.dict()
        logger.debug(f'validated_data = {pf(self.validated_data)}')
        return True if self.validated_data else False

    def push(self, netbox_client: NetboxClient) -> list[Record]:
        """
        Push data to Netbox
        :param netbox_client:
        :return:
        """
        results = []
        logger.debug(f'Pushing validated data to Netbox')
        logger.info(f'Adding Virtual Chassis {self.validated_data["name"]}')
        vc = netbox_client.add_virtual_chassis(name=self.validated_data['name'])
        logger.debug(f'Added Virtual Chassis {vc}')
        results.append(vc)
        for chassis in self.validated_data['members']:
            logger.info(f'Adding Chassis member {chassis["name"]}')
            chassis['virtual_chassis'] = vc.id
            member = netbox_client.add_virtual_chassis_member(chassis)
            logger.debug(f'Added Virtual Chassis member {member}')
            results.append(member)
            for device in chassis['devices']:
                logger.info(f'Adding device {device["name"]}')
                primary_ip4 = device.pop('primary_ip4', None)
                server = netbox_client.create_or_update_device(**device)
                logger.debug(f'Added device {server}')
                results.append(server)
                logger.info(f'Adding device {server.name} to Virtual Chassis member {member.name}')
                bay = netbox_client.add_device_bay(member, server, device['slot_id'])
                results.append(bay)
                logger.debug(f'Added device {server.name} to Virtual Chassis member {member.name}')
                results.extend(
                    netbox_client.add_interfaces(device=server.id, interfaces=device['interfaces']))
                results.extend(
                    netbox_client.add_ip_addresses(device=server.id, ip_addresses=device['ip_addresses']))
                results.extend(netbox_client.add_modules(device=server.id, modules=device['modules']))
                results.extend(
                    netbox_client.add_inventory_items(device=server.id,
                                                      inventory_items=device['inventory_items']))
                if primary_ip4 is not None:
                    logger.info(f'Checking if device {server.name} has primary IP {primary_ip4}')
                    if not server.primary_ip4 or server.primary_ip4.address != primary_ip4:
                        logger.info(f'Setting device {server.name} primary IP to {primary_ip4}')
                        server.primary_ip4 = primary_ip4
                        server.save()
                        logger.debug(f'Set device {server.name} primary IP to {primary_ip4}')
                    else:
                        logger.info(f'Device {server.name} already has primary IP {primary_ip4}')
        return results


class UcsmServerPlatformClient(BasePlatformClient, abc.ABC):
    management_handler: UcsmServerDeviceHandler
    os_handler: VcenterDeviceHandler

    def __init__(self, imported_data: dict, password_handler: Callable[[str], str] = None):
        super().__init__(imported_data, password_handler=password_handler)
        assert self.platform.lower() == 'ucsm_server', f'Platform {self.platform} is not supported by UCSM Server ' \
                                                       f'client'

    def _validate(self, data: list[dict]) -> list[NetboxDevice]:
        results = []
        for server in data:
            results.append(NetboxDevice(**server))
        return results

    def discover(self) -> bool:
        """
                Discover UCSM servers and compile into discovered_data
                :return:
                """
        results = self.management_handler.discover()
        # Set variables from imported data
        for server in results:
            server['rack'] = self.imported_data.get('rack', None)
            server['site'] = self.imported_data.get('site', None)
            server['tenant'] = self.imported_data.get('tenant', None)
            server['platform'] = self.imported_data.get('platform', None)
            server['cluster'] = self.imported_data.get('cluster', None)
            server['local_context_data'] = self.imported_data.get('local_context_data', None)
            server['custom_fields'] = combine_dict_values(server.get('custom_fields', {}), {
                "management_ip": self.management_ip,
                "management_username": self.management_username,
                "management_password": self.management_password,
                "os_ip": self.os_ip,
                "os_username": self.os_username,
                "os_password": self.os_password,
            })
            server['comments'] = self.imported_data.get('comments', None)
            server['tags'] = self.imported_data.get('tags', None)
            server['asset_tag'] = self.imported_data.get('asset_tag', None)
            server['position'] = self.imported_data.get('position', None)
            server['face'] = self.imported_data.get('face', None)
            server['airflow'] = self.imported_data.get('airflow', None)
            server['location'] = self.imported_data.get('location', None)
            server["status"] = 'active'
        if self.os_handler:
            for server in results:
                os_results = self.os_handler.discover_host(server['serial'])
                if not os_results:
                    logger.error(f'Could not discover OS data for {server["serial"]}')
                    raise ValueError(f'Could not discover OS data for {server["serial"]}')
                server['custom_fields']['os_ip'] = os_results['os_ip']
                server['name'] = os_results['name']
                server["primary_ip4"] = os_results['primary_ip4']
                server['interfaces'] = os_results['interfaces']
                server['ip_addresses'] = os_results['ip_addresses']
        self.discovered_data = results
        logger.info(f'Discovered UCSM data for {self.management_ip}:\n{pf(self.discovered_data)}')
        return True if self.discovered_data else False

    def is_valid(self) -> bool:
        self.validated_data = []
        validator = self._validate(self.discovered_data)
        for server in validator:
            self.validated_data.append(server.dict())
        logger.debug(f'validated_data = {pf(self.validated_data)}')
        return True if self.validated_data else False

    def push(self, netbox_client: NetboxClient) -> list[Record]:
        """
        Push data to Netbox
        :param netbox_client:
        :return:
        """
        results = []
        logger.debug(f'Pushing validated data to Netbox')
        for server in self.validated_data:
            logger.info(f'Adding device {server["name"]}')
            primary_ip4 = server.pop('primary_ip4', None)
            server_obj = netbox_client.create_or_update_device(**server)
            logger.debug(f'Added device {server_obj}')
            results.append(server_obj)
            results.extend(
                netbox_client.add_interfaces(device=server_obj.id, interfaces=server['interfaces']))
            results.extend(
                netbox_client.add_ip_addresses(device=server_obj.id, ip_addresses=server['ip_addresses']))
            results.extend(netbox_client.add_modules(device=server_obj.id, modules=server['modules']))
            results.extend(
                netbox_client.add_inventory_items(device=server_obj.id,
                                                  inventory_items=server['inventory_items']))
            if primary_ip4 is not None:
                logger.info(f'Checking if device {server_obj.name} has primary IP {primary_ip4}')
                if not server_obj.primary_ip4 or server_obj.primary_ip4.address != primary_ip4:
                    logger.info(f'Setting device {server_obj.name} primary IP to {primary_ip4}')
                    server_obj.primary_ip4 = primary_ip4
                    server_obj.save()
                    logger.debug(f'Set device {server_obj.name} primary IP to {primary_ip4}')
                else:
                    logger.info(f'Device {server_obj.name} already has primary IP {primary_ip4}')
        return results
