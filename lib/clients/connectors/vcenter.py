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
        self.virtual_machines = {}

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


class VcenterVirtualMachineHandler(BaseDeviceHandler):
    def __init__(self, ip: str, credentials: dict):
        super().__init__(ip, credentials)
        self.handler = self.connect()

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
        pass

    def discover_vm(self, vm_name: str) -> dict:
        """
        Discover the virtual machine in vCenter matching name
        :param vm_name:
        :return:
        """
        logger.debug(f'Discovering virtual machine {vm_name} in vCenter instance {self.ip}')
        virtual_machine = self.get_virtual_machine(vm_name)
        ip_addresses = self.get_ip_addresses(virtual_machine)
        primary_ip4 = None
        for ip in ip_addresses:
            if virtual_machine.guest.ipAddress in ip["address"]:
                primary_ip4 = ip["address"]
                break
        results = {
            "primary_ip4": primary_ip4,
            "device": virtual_machine.runtime.host.name,
            "vcpus": virtual_machine.config.hardware.numCPU,
            "memory": int(virtual_machine.config.hardware.memoryMB),
            "disk": self.get_disk_size(virtual_machine),
            "interfaces": self.get_interfaces(virtual_machine),
            "ip_addresses": ip_addresses,
            "custom_fields": {
                "os": virtual_machine.guest.guestFullName,
            }
        }
        logger.debug(f'Discovered virtual machine {vm_name} in vCenter instance {self.ip}: {pf(results)}')
        return results

    def get_virtual_machine(self, name: str) -> vim.VirtualMachine:
        """
        Get the virtual machine in vCenter instance using PyVmomi
        :return:
        """
        logger.debug(f'Getting virtual machine {name} for vCenter instance {self.ip}')
        content = self.handler.RetrieveContent()
        container = content.rootFolder  # starting point to look into
        view_type = [vim.VirtualMachine]  # object types to look for
        recursive = True  # whether we should look into it recursively
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive)
        for vm in container_view.view:
            if vm.name == name:
                logger.debug(f'Got virtual machine {name} for vCenter instance {self.ip}')
                logger.debug(f'Virtual machine {name} for vCenter instance {self.ip}: {pf(vm)}')
                return vm
            else:
                continue
        logger.debug(f'Virtual machine {name} for vCenter instance {self.ip} not found')
        raise ValueError(f'Virtual machine {name} for vCenter instance {self.ip} not found')

    def get_disk_size(self, virtual_machine: vim.VirtualMachine) -> int:
        """
        Get the disk size of a virtual machine in vCenter instance using PyVmomi
        :param virtual_machine:
        :return:
        """
        logger.debug(f'Getting disk size for virtual machine {virtual_machine.name} for vCenter instance {self.ip}')
        disk_size = 0
        for disk in virtual_machine.config.hardware.device:
            if isinstance(disk, vim.vm.device.VirtualDisk):
                disk_size += disk.capacityInKB
        logger.debug(f'Got disk size for virtual machine {virtual_machine.name} for vCenter instance {self.ip}: '
                     f'{pf(disk_size)}')
        disk_size = disk_size / 1024 / 1024
        return int(disk_size)

    def get_interfaces(self, virtual_machine: vim.VirtualMachine) -> list[dict]:
        """
        Get the interfaces for a virtual machine using PyVmomi
        :param virtual_machine:
        :return:
        """
        logger.debug(f'Getting interfaces for virtual machine {virtual_machine.name} for vCenter instance {self.ip}')
        interfaces = []
        for interface in virtual_machine.config.hardware.device:
            if (isinstance(interface, vim.vm.device.VirtualEthernetCard) or
                    isinstance(interface, vim.vm.device.VirtualVmxnet3)):
                interfaces.append({
                    "name": interface.deviceInfo.label,
                    "description": interface.deviceInfo.summary,
                    "mac_address": interface.macAddress,
                    "mtu": 1500
                })
        logger.debug(f'Got interfaces for virtual machine {virtual_machine.name} for vCenter instance {self.ip}: '
                     f'{pf(interfaces)}')
        return interfaces

    def get_ip_addresses(self, virtual_machine: vim.VirtualMachine) -> list[dict]:
        """
        Get the ip addresses for a virtual machine using PyVmomi
        :param virtual_machine:
        :return:
        """
        logger.debug(f'Getting ip addresses for virtual machine {virtual_machine.name} for vCenter instance {self.ip}')
        ip_addresses = []
        for nic in virtual_machine.guest.net:
            for ip in nic.ipConfig.ipAddress:
                if isinstance(ipaddress.ip_interface(f"{ip.ipAddress}/{ip.prefixLength}"), ipaddress.IPv6Interface):
                    continue
                address = ipaddress.ip_interface(f"{ip.ipAddress}/{ip.prefixLength}").exploded
                assigned_interface = None
                for interface in virtual_machine.config.hardware.device:
                    if (isinstance(interface, vim.vm.device.VirtualEthernetCard) or
                            isinstance(interface, vim.vm.device.VirtualVmxnet3)):
                        if interface.macAddress == nic.macAddress:
                            assigned_interface = interface.deviceInfo.label
                            break
                ip_addresses.append({
                    "assigned_object": assigned_interface,
                    "assigned_object_type": "virtualization.vminterface",
                    "address": address,
                    "status": "active"
                })
        logger.debug(f'Got ip addresses for virtual machine {virtual_machine.name} for vCenter instance {self.ip}: '
                     f'{pf(ip_addresses)}')
        return ip_addresses
