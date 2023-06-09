import abc
import ipaddress
import logging

from pyVim.connect import SmartConnect
from pyVmomi import vim
from pprint import pformat as pf

from lib.clients.connectors.base import BaseDeviceHandler
from lib.utils.lookup import get_wwn_hex

logger = logging.getLogger()


class VcenterDeviceHandler(BaseDeviceHandler, abc.ABC):

    def __init__(self, ip: str, credentials: dict):
        super().__init__(ip, credentials)
        self.handler = self.connect()
        self.hosts = {}

    def connect(self):
        """
        Connect to vCenter instance
        :return:
        """
        logger.debug(f'Connecting to vCenter instance {self.ip}')
        self.handler = SmartConnect(host=self.ip, user=self.username, pwd=self.password, disableSslCertValidation=True)
        logger.info(f'Successfully connected to vCenter instance {self.ip}')
        return self.handler

    def disconnect(self):
        """
        Disconnect from vCenter instance
        :return:
        """
        logger.debug(f'Disconnecting from vCenter instance {self.ip}')
        if not self.handler:
            logger.warning(f'No handler for vCenter instance {self.ip}')
            return
        self.handler.Disconnect()
        logger.info(f'Successfully disconnected from vCenter instance {self.ip}')

    def execute(self, command: str) -> str:
        pass

    def discover(self) -> dict:
        """
        Discover the interfaces and ip addresses of each host in vcenter
        :return:
        """
        results = {}
        logger.debug(f'Discovering interfaces and ip addresses for vCenter instance {self.ip}')
        for host in self.get_hosts():
            results[host.name] = {
                "serial": host.hardware.systemInfo.serialNumber,
                "interfaces": self.get_interfaces(host),
                "ip_addresses": self.get_ip_addresses(host)
            }
        logger.debug(f'Discovered interfaces and ip addresses for vCenter instance {self.ip}: {pf(results)}')
        return results

    def get_interfaces(self, host: vim.HostSystem) -> list[dict]:
        """
        Get the interfaces for a host using PyVmomi
        :return:
        """
        logger.debug(f'Getting interfaces for host {host.name}')
        interfaces = []
        interfaces.extend(self.get_ethernet_interfaces(host))
        interfaces.extend(self.get_ip_interfaces(host))
        interfaces.extend(self.get_fc_interfaces(host))
        logger.debug(f'Got interfaces for host {host.name}: {pf(interfaces)}')
        return interfaces

    @staticmethod
    def get_ip_addresses(host: vim.HostSystem) -> list[dict]:
        """
        Get the ip addresses for a host using PyVmomi
        :param host:
        :return:
        """
        logger.debug(f'Getting ip addresses for host {host.name}')
        ip_addresses = []
        for interface in host.config.network.vnic:
            ip_addresses.append({
                "assigned_object": interface.device,
                "assigned_object_type": "dcim.interface",
                "address": ipaddress.ip_interface(
                    f"{interface.spec.ip.ipAddress}/{interface.spec.ip.subnetMask}").exploded,
                "status": "active"
            })
        logger.debug(f'Got ip addresses for host {host.name}: {pf(ip_addresses)}')
        return ip_addresses

    def get_hosts(self) -> list[vim.HostSystem]:
        """
        Get the hosts in vCenter instance using PyVmomi
        :return:
        """
        logger.debug(f'Getting hosts for vCenter instance {self.ip}')
        hosts = []
        for datacenter in self.handler.content.rootFolder.childEntity:
            for cluster in datacenter.hostFolder.childEntity:
                hosts.extend(cluster.host)
        logger.debug(f'Got hosts for vCenter instance {self.ip}')
        logger.debug(f'Hosts for vCenter instance {self.ip}: {pf(hosts)}')
        return hosts

    @staticmethod
    def get_ethernet_interfaces(host: vim.HostSystem) -> list[dict]:
        """
        Get the ethernet interfaces for a host using PyVmomi
        :param host:
        :return:
        """
        logger.debug(f'Getting ethernet interfaces for host {host.name}')
        interfaces = []
        for interface in host.config.network.pnic:
            interface: vim.host.PhysicalNic
            interfaces.append({
                "name": interface.device,
                "description": "",
                "mac": interface.mac,
                "mtu": 1500,
                "speed": int(interface.linkSpeed.speedMb),
                "duplex": "full",
                "type": "40gbase-x-qsfpp" if interface.linkSpeed.speedMb == 40000 else "10gbase-x-sfpp",
            })
        logger.debug(f'Got ethernet interfaces for host {host.name}: {pf(interfaces)}')
        return interfaces

    @staticmethod
    def get_ip_interfaces(host: vim.HostSystem) -> list[dict]:
        """
        Get the ip interfaces for a host using PyVmomi
        :param host:
        :return:
        """
        logger.debug(f'Getting ip interfaces for host {host.name}')
        interfaces = []
        for interface in host.config.network.vnic:
            interface: vim.host.VirtualNic
            interfaces.append({
                "name": interface.device,
                "description": interface.portgroup,
                "mac": interface.spec.mac,
                "mtu": interface.spec.mtu,
                "speed": 10000,
                "duplex": "full",
                "type": "virtual",
            })
        logger.debug(f'Got ip interfaces for host {host.name}: {pf(interfaces)}')
        return interfaces

    @staticmethod
    def get_fc_interfaces(host: vim.HostSystem) -> list[dict]:
        """
        Get the fibre channel interfaces for a host using PyVmomi
        :param host:
        :return:
        """
        logger.debug(f'Getting fibre channel interfaces for host {host.name}')
        interfaces = []
        for interface in host.config.storageDevice.hostBusAdapter:
            if not isinstance(interface, vim.host.FibreChannelHba):
                continue
            interface: vim.host.FibreChannelHba
            interfaces.append({
                "name": interface.device,
                "wwn": get_wwn_hex(interface.portWorldWideName),
                "description": interface.model,
                "speed": int(interface.speed),
                "duplex": "full",
                "type": "32gfc-sfp28" if int(interface.speed) == 32 else "16gfc-sfpp",
            })
        logger.debug(f'Got fibre channel interfaces for host {host.name}: {pf(interfaces)}')
        return interfaces

    def discover_host(self, host_serial: str) -> dict:
        """
        Discover the host in vCenter matching IP
        :param host_serial:
        :return:
        """
        logger.debug(f'Discovering host {host_serial} in vCenter instance {self.ip}')
        if not self.hosts:
            for host in self.get_hosts():
                serial = host.hardware.systemInfo.serialNumber
                if serial is None:
                    for id_info in host.hardware.systemInfo.otherIdentifyingInfo:
                        if id_info.identifierType.key == "ServiceTag":
                            serial = id_info.identifierValue
                            break
                logger.debug(f'Host {host.name} has serial {serial}')
                self.hosts[serial] = host
        try:
            logger.debug(f'Checking host serial {host_serial} in vcenter instance {self.ip}')
            host = self.hosts[host_serial]
            ip = ipaddress.ip_interface(f'{host.config.network.vnic[0].spec.ip.ipAddress}/'
                                        f'{host.config.network.vnic[0].spec.ip.subnetMask}').exploded
            results = {
                "name": host.name,
                "os_ip": host.config.network.vnic[0].spec.ip.ipAddress,
                "primary_ip4": ip,
                "interfaces": self.get_interfaces(host),
                "ip_addresses": self.get_ip_addresses(host)
            }
            logger.debug(f'Discovered host {host_serial} in vCenter instance {self.ip}: {pf(results)}')
            return results
        except KeyError:
            logger.error(f'Failed to discover host {host_serial} in vCenter instance {self.ip}')
        raise ValueError(f'Failed to discover host {host_serial} in vCenter instance {self.ip}')

    def get_clusters(self):
        """
        Get the clusters in vCenter instance using PyVmomi
        :return:
        """
        logger.debug(f'Getting clusters for vCenter instance {self.ip}')
        clusters = []
        for datacenter in self.handler.content.rootFolder.childEntity:
            for cluster in datacenter.hostFolder.childEntity:
                clusters.append(cluster)
        logger.debug(f'Got clusters for vCenter instance {self.ip}')
        logger.debug(f'Clusters for vCenter instance {self.ip}: {pf(clusters)}')
        return clusters

