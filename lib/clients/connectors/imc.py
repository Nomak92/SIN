import ipaddress
import pprint
from pprint import pformat as pf
import imcsdk.imchandle
from imcsdk.apis.server.inventory import inventory_get
from lib.clients.connectors.base import BaseDeviceHandler
from lib.utils.lookup import get_manufacturer, get_memory_manufacturer, get_memory_location
import logging
logger = logging.getLogger()


class ImcDeviceHandler(BaseDeviceHandler):

    def __init__(self, ip: str, credentials: dict):
        super().__init__(ip, credentials)
        logger.debug(f"Instantiating IMC device handler for {ip}")
        self.handler = self.connect()
        self.inventory = self.get_inventory_data()
        self.sys = self.handler.query_dn("sys/rack-unit-1")
        self.sys_mgmt = self.handler.query_dn('sys/rack-unit-1/mgmt/if-1')

    def connect(self):
        logger.debug(f"Connecting to IMC device {self.ip}")
        handler = imcsdk.imchandle.ImcHandle(self.ip, self.username, self.password)
        if handler.login():
            logger.info(f'Successfully logged into IMC device {self.ip}')
            return handler
        else:
            raise ConnectionError("Failed to connect to IMC device")

    def disconnect(self):
        logger.debug(f"Disconnecting from IMC device {self.ip}")
        if self.handler.logout():
            logger.info(f'Successfully logged out of IMC device {self.ip}')
        else:
            raise ConnectionError("Failed to disconnect from IMC device")

    def execute(self, command: str) -> str:
        pass

    def get_inventory_data(self):
        logger.debug(f'Retrieving Inventory data for {self.ip}')
        inventory_data = inventory_get(self.handler)
        for host in inventory_data.keys():
            logger.debug(f'Inventory data for {host} = {pprint.pformat(inventory_data[host])}')
            return inventory_data[host]

    def discover(self) -> dict:
        """
            Discover device and return results
        :return: dict
        """
        logger.debug(f'Discovering device {self.ip}')
        results = {
            "serial": self.get_serial(),
            "device_type": self.get_model(),
            "custom_fields": {
                "bios_version": self.get_bios_version(),
                "fw_version": self.get_platform_version(),
                "cpu_cores": self.get_cpu_cores_total(),
                "memory_gb": self.get_memory_total(),
            },
            "modules": self.get_modules(),
            "inventory_items": self.get_inventory_items(),
            "primary_ip4": self.get_primary_ip4(),
            "interfaces": self.get_interfaces(),
            "ip_addresses": self.get_ip_addresses(),
        }
        return results

    def get_serial(self) -> str:
        """
            Get device serial number
        :return: str
        """
        logger.debug(f'Serial: {self.sys.serial}')
        return self.sys.serial

    def get_model(self):
        """
            Get device model
        :return: str
        """
        logger.debug(f'Model: {self.sys.model}')
        return self.sys.model

    def get_bios_version(self):
        """
            Get device bios version
        :return: str
        """
        result = self.handler.query_dn("sys/rack-unit-1/bios/fw-boot-loader").version.strip()
        logger.debug(f"BIOS Version: {result}")
        return result

    def get_platform_version(self):
        """
            Get device platform version
        :return: str
        """
        result = self.handler.query_dn('sys/rack-unit-1/mgmt/fw-system').version.strip()
        logger.debug(f"Platform Version: {result}")
        return result

    def get_cpu_cores_total(self):
        """
            Get total number of CPU cores
        :return: int
        """
        logger.debug(f'CPU Cores: {self.sys.num_of_cores}')
        return int(self.sys.num_of_cores)

    def get_memory_total(self):
        """
            Get total amount of memory
        :return: int
        """
        logger.debug(f'Memory: {int(self.sys.total_memory) / 1024} GB')
        return int(self.sys.total_memory) / 1024

    def get_modules(self):
        """
                Get all modules with the following data:
                - Modules
                    - Module Bay (Slot)
                    - * Module Types
                        - Manufacturer
                        - Model (Module Type)
                        - Part Number (if available)
                    - Module (Modules in Bays)
                        - Module Type
                        - Module Bay
                        - Serial Number (if available)
                        - Firmware Version (if available)
                :return:
                """
        logger.debug(f'Retrieving modules for {self.ip}')
        results = []
        results.extend(self.get_pci_modules())
        results.extend(self.get_storage_modules())
        logger.debug(f'Retrieved modules for {self.ip}: {pf(results)}')
        return results

    def get_inventory_items(self):
        logger.debug(f'Retrieving inventory items for {self.ip}')
        results = []
        results.extend(self.get_drives())
        results.extend(self.get_cpus())
        results.extend(self.get_memory())
        logger.debug(f'Retrieved inventory items for {self.ip}: {pf(results)}')
        return results

    def get_primary_ip4(self):
        """
            Get primary IPv4 address with cidr
        :return: str
        """
        result = ipaddress.ip_interface(f"{self.sys_mgmt.ext_ip}/{self.sys_mgmt.ext_mask}").exploded
        logger.debug(f"Primary IPv4: {result}")
        return result

    def get_interfaces(self):
        logger.debug(f'Retrieving interfaces for {self.ip}')
        results = []
        result = {
            "name": "MGMT",
            "description": self.sys_mgmt.description,
            "mac": self.sys_mgmt.mac,
            "type": "1000base-t",
            "speed": 1000,
            "duplex": "full",
            "mtu": 1500,
        }
        results.append(result)
        logger.debug(f'Retrieved interfaces for {self.ip}: {pf(results)}')
        return results

    def get_ip_addresses(self):
        logger.debug(f'Retrieving IP addresses for {self.ip}')
        results = []
        result = {
            "assigned_object": "MGMT",
            "assigned_object_type": "dcim.interface",
            "address": ipaddress.ip_interface(f"{self.sys_mgmt.ext_ip}/{self.sys_mgmt.ext_mask}").exploded,
            "status": "active",
        }
        results.append(result)
        logger.debug(f'Retrieved IP addresses for {self.ip}: {pf(results)}')
        return results

    def get_pci_modules(self) -> list[dict]:
        logger.debug(f'Retrieving PCI modules for {self.ip}')
        results = []
        for pci in self.inventory['pci']:
            if 'HBA' in pci['id'] or 'RAID' in pci['id']:
                continue
            result = {
                "manufacturer": get_manufacturer(pci["model"]),
                "module_type": pci['model'],
                "module_bay": f'SLOT-{pci["id"]}' if 'SLOT' not in pci['id'] else pci['id'],
                "custom_fields": {
                    "fw_version": pci['version']
                },
            }
            results.append(result)
        logger.debug(f'Retrieved PCI modules for {self.ip}: {pf(results)}')
        return results

    def get_storage_modules(self) -> list[dict]:
        logger.debug(f'Retrieving storage modules for {self.ip}')
        results = []
        for storage in self.inventory['storage']:
            result = {
                "manufacturer": get_manufacturer(storage['vendor']),
                "module_type": storage['model'],
                "module_bay": f"SLOT-{storage['pci_slot']}" if 'SLOT' not in storage['pci_slot'] else
                storage['pci_slot'],
                "serial": storage.get('serial', "N/A"),
                "custom_fields": {
                    "fw_version": storage.get('firmware_package_build', "N/A")
                },
            }
            results.append(result)
        logger.debug(f'Retrieved storage modules for {self.ip}: {pf(results)}')
        return results

    def get_drives(self):
        """
            Get all drives with the following data:
            - Drives
                - Name
                - Manufacturer
                - Model (Drive Type)
                - Media Type (Role)
                - Serial Number (if available)
                - Firmware Version (if available)
                - Capacity (GB)
        :return:
        """
        logger.debug(f'Retrieving drives for {self.ip}')
        results = []
        for disk in self.inventory['disks']:
            if not disk['product_id']:
                continue
            result = {
                "part_id": disk['product_id'],
                "name": f"PD-{disk['id']}",
                "manufacturer": get_manufacturer(disk['product_id']),
                "role": disk['media_type'],
                "serial": disk.get('drive_serial_number', "N/A"),
                "custom_fields": {
                    "fw_version": disk.get('drive_firmware', "N/A"),
                    "size": f'{int(disk["coerced_size"].split(" ")[0]) / 1024}GB' if disk['coerced_size'] else "N/A",
                }
            }
            results.append(result)
        flash_drives_query = self.handler.query_classid(class_id="StorageFlexFlashPhysicalDrive")
        for flash_drive in flash_drives_query:
            result = {
                "part_id": flash_drive.product_name,
                "name": flash_drive.slot_number,
                "manufacturer": get_manufacturer(flash_drive.manufacturer_id),
                "role": "Flash",
                "serial": flash_drive.serial_number,
                "custom_fields": {
                    "fw_version": flash_drive.product_revision,
                    "size": f"{int(flash_drive.capacity.split(' ')[0]) / 1024}GB",
                },
            }
            results.append(result)
        logger.debug(f'Retrieved drives for {self.ip}: {pf(results)}')
        return results

    def get_cpus(self):
        """
        Get all CPUs with the following data:
            - CPUs
                - Name
                - Manufacturer
                - Model (CPU Type)
                - Speed (MHz)
                - Cores
        :return:
        """
        logger.debug(f'Retrieving CPUs for {self.ip}')
        results = []
        for cpu in self.inventory['cpu']:
            details = self.handler.query_dn(cpu["dn"])
            result = {
                "part_id": details.model,
                "name": details.socket_designation,
                "role": "CPU",
                "manufacturer": "Intel" if 'Intel' in details.vendor else "AMD",
                "custom_fields": {
                    "size": details.cores,
                    "speed": f"{int(details.speed) / 1000}GHz",
                }
            }
            results.append(result)
        logger.debug(f'Retrieved CPUs for {self.ip}: {pf(results)}')
        return results

    def get_memory(self):
        """
        Get all memory with the following data:
            - Memory
                - Name
                - Manufacturer
                - Model (Memory Type)
                - Speed (MHz)
                - Capacity (GB)
        :return:
        """
        logger.info(f'Retrieving memory modules for {self.ip}')
        results = []
        for memory in self.inventory['memory']:
            logger.debug(f"Retrieving memory module {memory['id']}")
            # details = self.handler.query_dn(memory["dn"])
            result = {
                "part_id": memory["model"].strip(),
                "name": get_memory_location(self.sys.model, memory["id"]),
                "role": "Memory",
                "serial": memory["serial"],
                "manufacturer": get_memory_manufacturer(memory["vendor"]),
                "custom_fields": {
                    "speed": f"{memory['clock']}MHz",
                    "size": f"{int(memory['capacity']) / 1024}GB",
                }
            }
            results.append(result)
        logger.debug(f'Retrieved memory modules for {self.ip}: {pf(results)}')
        return results
