import abc
import logging

from ucsmsdk.mometa.adaptor.AdaptorUnit import AdaptorUnit
from ucsmsdk.mometa.compute import ComputeBlade, ComputeRackUnit
from ucsmsdk.mometa.storage.StorageController import StorageController
from ucsmsdk.mometa.storage.StorageFlexFlashController import StorageFlexFlashController
from ucsmsdk.ucshandle import UcsHandle
from lib.clients.connectors.base import BaseDeviceHandler
from pprint import pformat as pf

from lib.utils.lookup import get_memory_manufacturer, get_manufacturer

logger = logging.getLogger()


class UcsmChassisDeviceHandler(BaseDeviceHandler, abc.ABC):

    def __init__(self, ip: str, credentials: dict):
        super().__init__(ip, credentials)
        self.handler = self.connect()
        self.vc = self.get_virtual_chassis_name()

    def connect(self):
        """
        Connect to the UCSM device
        :return:
        """
        logger.info(f'Connecting to UCSM device {self.ip}')
        self.handler = UcsHandle(self.ip, self.username, self.password)
        self.handler.login()
        return self.handler

    def disconnect(self):
        """
        Disconnect from the UCSM device
        :return:
        """
        logger.debug(f'Disconnecting from UCSM device {self.ip}')
        if not self.handler:
            logger.warning(f'No handler for UCSM device {self.ip}')
            return
        self.handler.logout()
        logger.info(f'Disconnected from UCSM device {self.ip}')

    def execute(self, command: str) -> str:
        pass

    def discover(self) -> dict:
        """
        Discover the UCSM device
        :return:
        """
        logger.debug(f'Discovering UCSM device {self.ip}')
        results = {
            "name": self.vc,
            "members": self.get_chassis()
        }
        logger.info(f'UCSM device {self.ip} discovery results: {pf(results)}')
        return results

    def _query_dn(self, dn):
        """
        Query the UCSM device for a specific DN
        :param dn:
        :return:
        """
        logger.debug(f'Querying UCSM device {self.ip} for DN {dn}')
        return self.handler.query_dn(dn)

    def _query_class_id(self, class_id):
        """
        Query the UCSM device for a specific class ID
        :param class_id:
        :return:
        """
        logger.debug(f'Querying UCSM device {self.ip} for class ID {class_id}')
        return self.handler.query_classid(class_id=class_id)

    def _query_children(self, dn: str, class_id: str = None):
        """
        Query the UCSM device for the children of a specific DN
        :param dn:
        :return:
        """
        logger.debug(f'Querying UCSM device {self.ip} for children of DN {dn} with class ID {class_id}')
        return self.handler.query_children(in_dn=dn, class_id=class_id)

    def get_bios_version(self, device_dn: ComputeBlade) -> str:
        """
        Get the BIOS version of the UCSM device
        :return:
        """
        logger.info(f'Getting BIOS version for UCSM device {self.ip}')
        results = self._query_dn(f"{device_dn.dn}/bios/fw-boot-loader").version
        logger.debug(f'UCSM device {self.ip} BIOS version: {results}')
        return results

    def get_modules(self, device_dn: ComputeBlade) -> list[dict]:
        """
        Get the modules in the UCSM device
        :param device_dn:
        :return:
        """
        logger.info(f'Getting modules for UCSM device {self.ip}')
        results = []
        results.extend(self.get_adaptors(device_dn))
        results.extend(self.get_flash_controllers(device_dn))
        logger.debug(f'UCSM device {self.ip} modules: {pf(results)}')
        return results

    def get_adaptors(self, device_dn: ComputeBlade) -> list[dict]:
        """
        Get the adaptors in the UCSM device
        :param device_dn:
        :return:
        """
        logger.info(f'Getting adaptors for UCSM device {self.ip}')
        results = []
        for adaptor_dn in self._query_children(dn=f"{device_dn.dn}", class_id='AdaptorUnit'):
            results.append({
                "manufacturer": get_manufacturer(adaptor_dn.vendor),
                "module_type": adaptor_dn.model,
                "module_bay": f'Adaptor-{adaptor_dn.id}',
                "custom_fields": {
                    "fw_version": self.get_adaptor_firmware_version(adaptor_dn),
                },
            })
        logger.debug(f'UCSM device {self.ip} adaptors: {pf(results)}')
        return results

    def get_drives(self, device_dn: ComputeBlade) -> list[dict]:
        """
        Get the drives in the UCSM device
        :param device_dn:
        :return:
        """
        logger.info(f'Getting drives for UCSM device {self.ip}')
        results = []
        for drive_dn in self._query_children(dn=f"{device_dn.dn}", class_id='StorageFlexFlashController'):
            drive = self._query_dn(drive_dn.dn)
            results.append({
                "part_id": drive.model,
                "name": f'SLOT-{drive.id}',
                "role": "Flash",
                "manufacturer": get_manufacturer(drive.vendor),
                "serial": drive.serial,
                "custom_fields": {
                    "size": f"{int(drive.size) / 1024}GB",
                }
            })
        logger.debug(f'UCSM device {self.ip} drives: {pf(results)}')
        return results

    def get_cpus(self, device_dn: ComputeBlade) -> list[dict]:
        """
        Get the CPUs in the UCSM device
        :return:
        """
        logger.info(f'Getting CPUs for UCSM device {self.ip}')
        results = []
        for cpu_dn in self._query_children(dn=f"{device_dn.dn}/board", class_id='ProcessorUnit'):
            results.append({
                "part_id": cpu_dn.model,
                "name": cpu_dn.socket_designation,
                "role": "CPU",
                "manufacturer": "Intel" if 'Intel' in cpu_dn.vendor else "AMD",
                "custom_fields": {
                    "size": cpu_dn.cores,
                    "speed": f"{float(cpu_dn.speed)}GHz",
                }
            })
        logger.debug(f'UCSM device {self.ip} CPUs: {pf(results)}')
        return results

    def get_memory(self, device_dn: ComputeBlade) -> list[dict]:
        logger.info(f'Retrieving memory modules for {self.ip}')
        results = []
        mem_array = self._query_children(dn=f"{device_dn.dn}/board", class_id='MemoryArray')
        for array in mem_array:
            for mem in self._query_children(dn=array.dn, class_id='MemoryUnit'):
                if not mem.model:
                    continue
                results.append({
                    "part_id": mem.model.strip(),
                    "name": mem.location,
                    "role": "Memory",
                    "manufacturer": get_memory_manufacturer(mem.vendor),
                    "serial": mem.serial,
                    "custom_fields": {
                        "size": f"{int(mem.capacity) / 1024}GB" if mem.capacity != "unspecified" else "N/A",
                        "speed": f"{int(mem.clock)}MHz" if mem.clock != 'unspecified' else "N/A",
                    }
                })
        logger.debug(f'Retrieved memory modules for {self.ip}: {pf(results)}')
        return results

    def get_virtual_chassis_name(self) -> str:
        """
        Get the virtual chassis name of the UCSM device
        :return:
        """
        logger.info(f'Getting virtual chassis name for UCSM device {self.ip}')
        results = self._query_dn('sys').name
        logger.debug(f'UCSM device {self.ip} virtual chassis name: {results}')
        return results

    def get_devices(self, chassis_id: int) -> list[dict]:
        """
        Get the devices in the UCSM device
        :return:
        """
        logger.debug(f'Getting devices for UCSM device {self.ip}')
        devices = []
        for device_dn in self._query_class_id('ComputeBlade'):
            if device_dn.chassis_id != chassis_id:
                continue
            devices.append({
                'device_type': device_dn.model,
                "device_role": "Blade Server",
                'slot_id': int(device_dn.slot_id),
                'serial': device_dn.serial,
                'modules': self.get_modules(device_dn),
                'inventory_items': self.get_inventory_items(device_dn),
                "custom_fields": {
                    "bios_version": self.get_bios_version(device_dn),
                    "fw_version": self.get_platform_version(device_dn),
                    "cpu_cores": int(device_dn.num_of_cores),
                    "memory_gb": int(int(device_dn.total_memory) / 1024),
                }
            })
        logger.debug(f'UCSM device {self.ip} devices: {pf(devices)}')
        return devices

    def get_chassis(self) -> list[dict]:
        """
        Get the chassis in the UCSM device
        :return:
        """
        logger.debug(f'Getting chassis for UCSM device {self.ip}')
        chassis = []
        for chassis_dn in self._query_class_id('EquipmentChassis'):
            chassis.append({
                'name': f'{self.vc}:{chassis_dn.id}',
                'device_type': chassis_dn.model,
                "device_role": "Chassis",
                'serial': chassis_dn.serial,
                'virtual_chassis': self.vc,
                'vc_position': chassis_dn.id,
                'devices': self.get_devices(chassis_id=chassis_dn.id),
                'custom_fields': {},
            })
        logger.debug(f'UCSM device {self.ip} chassis: {pf(chassis)}')
        return chassis

    def get_inventory_items(self, device_dn: ComputeBlade) -> list[dict]:
        """
        Get the inventory items in the UCSM device
        :return:
        """
        logger.debug(f'Getting inventory items for UCSM device {self.ip}')
        inventory_items = []
        inventory_items.extend(self.get_cpus(device_dn))
        inventory_items.extend(self.get_memory(device_dn))
        inventory_items.extend(self.get_drives(device_dn))
        logger.debug(f'UCSM device {self.ip} inventory items: {pf(inventory_items)}')
        return inventory_items

    def get_platform_version(self, device_dn: ComputeBlade) -> str:
        """
        Get the platform version of the UCSM device
        :param device_dn:
        :return:
        """
        logger.info(f'Getting platform version for UCSM device {self.ip}')
        results = self._query_dn(f"{device_dn.dn}/mgmt/fw-system").version
        logger.debug(f'UCSM device {self.ip} platform version: {results}')
        return results

    def get_adaptor_firmware_version(self, adaptor_dn: AdaptorUnit) -> str:
        """
        Get the adaptor firmware version of the UCSM device
        :param adaptor_dn:
        :return:
        """
        logger.info(f'Getting adaptor firmware version for UCSM device {self.ip}')
        results = self._query_dn(f"{adaptor_dn.dn}/mgmt/fw-system").version
        logger.debug(f'UCSM device {self.ip} adaptor firmware version: {results}')
        return results

    def get_flash_controllers(self, device_dn: ComputeBlade) -> list[dict]:
        """
        Get the flash controllers in the UCSM device
        :param device_dn:
        :return:
        """
        logger.info(f'Getting flash controllers for UCSM device {self.ip}')
        results = []
        for flash_dn in self._query_children(dn=f"{device_dn.dn}/board", class_id='StorageFlexFlashController'):
            results.append({
                "manufacturer": get_manufacturer(flash_dn.vendor),
                "module_type": flash_dn.model,
                "module_bay": f"Storage-flexflash-{flash_dn.id}",
                "serial": flash_dn.serial,
                "custom_fields": {
                    "fw_version": self.get_flash_controller_firmware_version(flash_dn),
                },
            })
        logger.debug(f'UCSM device {self.ip} flash controllers: {pf(results)}')
        return results

    def get_flash_controller_firmware_version(self, flash_dn: StorageFlexFlashController) -> str:
        """
        Get the flash controller firmware version of the UCSM device
        :param flash_dn:
        :return:
        """
        logger.info(f'Getting flash controller firmware version for UCSM device {self.ip}')
        results = self._query_dn(f"{flash_dn.dn}/fw-system").version
        logger.debug(f'UCSM device {self.ip} flash controller firmware version: {results}')
        return results


class UcsmServerDeviceHandler(BaseDeviceHandler, abc.ABC):
    def __init__(self, ip: str, credentials: dict):
        super().__init__(ip, credentials)
        self.handler = self.connect()

    def connect(self):
        """
        Connect to the UCSM device
        :return:
        """
        logger.info(f'Connecting to UCSM device {self.ip}')
        self.handler = UcsHandle(self.ip, self.username, self.password)
        self.handler.login()
        return self.handler

    def disconnect(self):
        """
        Disconnect from the UCSM device
        :return:
        """
        logger.debug(f'Disconnecting from UCSM device {self.ip}')
        if not self.handler:
            logger.warning(f'No handler for UCSM device {self.ip}')
            return
        self.handler.logout()
        logger.info(f'Disconnected from UCSM device {self.ip}')

    def execute(self, command: str) -> str:
        pass

    def discover(self) -> list[dict]:
        """
        Discover the UCSM device
        :return:
        """
        logger.debug(f'Discovering UCSM device {self.ip}')
        results = []
        for server_dn in self._query_class_id(class_id='ComputeRackUnit'):
            device_role = "Rack Server"
            if "HX" in server_dn.model:
                device_role = "HyperFlex"
            elif "B200" in server_dn.model:
                device_role = "Blade"
            results.append({
                'device_type': server_dn.model,
                "device_role": device_role,
                'serial': server_dn.serial,
                'modules': self.get_modules(server_dn),
                'inventory_items': self.get_inventory_items(server_dn),
                "custom_fields": {
                    "bios_version": self.get_bios_version(server_dn),
                    "fw_version": self.get_platform_version(server_dn),
                    "cpu_cores": int(server_dn.num_of_cores),
                    "memory_gb": int(int(server_dn.total_memory) / 1024),
                }
            })
        logger.info(f'UCSM device {self.ip} discovery results: {pf(results)}')
        return results

    def _query_dn(self, dn):
        """
        Query the UCSM device for a specific DN
        :param dn:
        :return:
        """
        logger.debug(f'Querying UCSM device {self.ip} for DN {dn}')
        return self.handler.query_dn(dn)

    def _query_class_id(self, class_id) -> list:
        """
        Query the UCSM device for a specific class ID
        :param class_id:
        :return:
        """
        logger.debug(f'Querying UCSM device {self.ip} for class ID {class_id}')
        return self.handler.query_classid(class_id=class_id)

    def _query_children(self, dn: str, class_id: str = None) -> list:
        """
        Query the UCSM device for the children of a specific DN
        :param dn:
        :return:
        """
        logger.debug(f'Querying UCSM device {self.ip} for children of DN {dn} with class ID {class_id}')
        return self.handler.query_children(in_dn=dn, class_id=class_id)

    def get_modules(self, server_dn: ComputeRackUnit) -> list[dict]:
        logger.info(f'Getting modules for UCSM device {self.ip}')
        results = []
        results.extend(self.get_adaptors(server_dn))
        results.extend(self.get_storage_controllers(server_dn))
        logger.debug(f'UCSM device {self.ip} modules: {pf(results)}')
        return results

    def get_inventory_items(self, server_dn: ComputeRackUnit) -> list[dict]:
        """
        Get the inventory items in the UCSM device
        :return:
        """
        logger.debug(f'Getting inventory items for UCSM device {self.ip}')
        inventory_items = []
        inventory_items.extend(self.get_cpus(server_dn))
        inventory_items.extend(self.get_memory(server_dn))
        inventory_items.extend(self.get_drives(server_dn))
        logger.debug(f'UCSM device {self.ip} inventory items: {pf(inventory_items)}')
        return inventory_items

    def get_bios_version(self, server_dn: ComputeRackUnit) -> str:
        """
        Get the BIOS version of the UCSM device
        :return:
        """
        logger.info(f'Getting BIOS version for UCSM device {self.ip}')
        results = self._query_dn(f"{server_dn.dn}/bios/fw-boot-loader").version
        logger.debug(f'UCSM device {self.ip} BIOS version: {results}')
        return results

    def get_platform_version(self, server_dn: ComputeRackUnit) -> str:
        """
        Get the platform version of the UCSM device
        :param server_dn:
        :return:
        """
        logger.info(f'Getting platform version for UCSM device {self.ip}')
        results = self._query_dn(f"{server_dn.dn}/mgmt/fw-system").version
        logger.debug(f'UCSM device {self.ip} platform version: {results}')
        return results

    def get_adaptors(self, server_dn: ComputeRackUnit) -> list[dict]:
        """
        Get the adapters in the UCSM device
        :param server_dn:
        :return:
        """
        logger.info(f'Getting adaptors for UCSM device {server_dn.name}')
        results = []
        for adaptor_dn in self._query_children(dn=f"{server_dn.dn}", class_id='AdaptorUnit'):
            results.append({
                "manufacturer": get_manufacturer(adaptor_dn.vendor),
                "module_type": adaptor_dn.model,
                "module_bay": f'SLOT-{adaptor_dn.pci_slot}',
                "custom_fields": {
                    "fw_version": self.get_adaptor_firmware_version(adaptor_dn),
                },
            })
        logger.debug(f'UCSM device {self.ip} adaptors: {pf(results)}')
        return results

    def get_storage_controllers(self, server_dn: ComputeRackUnit) -> list[dict]:
        """
        Get the storage controllers in the UCSM device
        :param server_dn:
        :return:
        """
        logger.info(f'Getting storage controllers for UCSM device {server_dn.name}')
        results = []
        for storage_controller_dn in self._query_children(dn=f"{server_dn.dn}/board", class_id='StorageController'):
            results.append({
                "manufacturer": get_manufacturer(storage_controller_dn.vendor),
                "module_type": storage_controller_dn.model,
                "module_bay": f'{storage_controller_dn.rn.upper()}',
                "serial": storage_controller_dn.serial,
                "custom_fields": {
                    "fw_version": self.get_storage_controller_firmware_version(storage_controller_dn),
                },
            })
        logger.debug(f'UCSM device {self.ip} storage controllers: {pf(results)}')
        return results

    def get_adaptor_firmware_version(self, adaptor_dn: AdaptorUnit) -> str:
        """
        Get the adaptor firmware version of the UCSM device
        :param adaptor_dn:
        :return:
        """
        logger.info(f'Getting adaptor firmware version for UCSM device {self.ip}')
        results = self._query_dn(f"{adaptor_dn.dn}/mgmt/fw-system").version
        logger.debug(f'UCSM device {self.ip} adaptor firmware version: {results}')
        return results

    def get_storage_controller_firmware_version(self, storage_controller_dn: StorageController) -> str:
        """
        Get the storage controller firmware version of the UCSM device
        :param storage_controller_dn:
        :return:
        """
        logger.info(f'Getting storage controller firmware version for UCSM device {self.ip}')
        results = self._query_dn(f"{storage_controller_dn.dn}/fw-system")
        if results is None:
            logger.debug(f'Unable to get storage controller firmware version for {storage_controller_dn.rn.upper()}')
            return "N/A"
        else:
            logger.debug(f'UCSM device {self.ip} storage controller firmware version: {results.version}')
            return results.version

    def get_cpus(self, server_dn: ComputeRackUnit) -> list[dict]:
        """
        Get the CPUs in the UCSM device
        :return:
        """
        logger.info(f'Getting CPUs for UCSM device {self.ip}')
        results = []
        for cpu_dn in self._query_children(dn=f"{server_dn.dn}/board", class_id='ProcessorUnit'):
            results.append({
                "part_id": cpu_dn.model if cpu_dn.model else "N/A",
                "name": cpu_dn.socket_designation,
                "role": "CPU",
                "manufacturer": "Intel" if 'Intel' in cpu_dn.vendor else "AMD",
                "custom_fields": {
                    "size": cpu_dn.cores,
                    "speed": f"{float(cpu_dn.speed)}GHz",
                }
            })
        logger.debug(f'UCSM device {self.ip} CPUs: {pf(results)}')
        return results

    def get_memory(self, server_dn: ComputeRackUnit) -> list[dict]:
        """
        Get the memory in the UCSM device
        :param server_dn:
        :return:
        """
        logger.info(f'Retrieving memory modules for {self.ip}')
        results = []
        mem_array = self._query_children(dn=f"{server_dn.dn}/board", class_id='MemoryArray')
        for array in mem_array:
            for mem in self._query_children(dn=array.dn, class_id='MemoryUnit'):
                results.append({
                    "part_id": mem.model.strip() if mem.model else "N/A",
                    "name": mem.location,
                    "role": "Memory",
                    "manufacturer": get_memory_manufacturer(mem.vendor),
                    "serial": mem.serial,
                    "custom_fields": {
                        "size": f"{int(mem.capacity) / 1024}GB" if mem.capacity != "unspecified" else "N/A",
                        "speed": f"{int(mem.clock)}MHz" if mem.clock != 'unspecified' else "N/A",
                    }
                })
        logger.debug(f'Retrieved memory modules for {self.ip}: {pf(results)}')
        return results

    def get_drives(self, server_dn: ComputeRackUnit) -> list[dict]:
        """
        Get the drives in the UCSM device
        :param server_dn:
        :return:
        """
        logger.info(f'Retrieving drives for {server_dn.rn}')
        results = []
        for slot_dn in self._query_children(dn=f"{server_dn.dn}/board", class_id='StorageLocalDiskSlotEp'):
            if not slot_dn.presence == 'equipped':
                continue
            disk = self._query_dn(slot_dn.peer_dn)
            results.append({
                "part_id": disk.model if disk.model else "N/A",
                "name": f'{disk.rn.upper()}',
                "role": f'{disk.device_type}',
                "manufacturer": get_manufacturer(disk.vendor),
                "serial": disk.serial,
                "custom_fields": {
                    "size": f"{int(disk.size) / 1024}GB",
                }
            })
        for slot_dn in self._query_children(dn=f"{server_dn.dn}/board", class_id='StorageController'):
            if not slot_dn.presence == 'equipped':
                continue
            for disk in self._query_children(dn=slot_dn.dn, class_id='StorageLocalDisk'):
                if not disk.presence == 'equipped':
                    continue
                results.append({
                    "part_id": disk.model if disk.model else "N/A",
                    "name": f'{disk.rn.upper()}',
                    "role": f'{disk.device_type}',
                    "manufacturer": get_manufacturer(disk.vendor),
                    "serial": disk.serial,
                    "custom_fields": {
                        "size": f"{int(disk.size) / 1024}GB",
                    }
                })
        logger.debug(f'Retrieved drives for {server_dn.rn}: {pf(results)}')
        return results
