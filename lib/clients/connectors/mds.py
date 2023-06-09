import abc
import ipaddress
import re
from lib.utils.parsers import fsm_parser, fsm_template_mds_show_interface_fc, fsm_template_mds_show_interface_mgmt
from lib.clients.connectors.base import BaseDeviceHandler
from lib.utils.logs import create_logger
from unicon import Connection
from genie.libs.parser.nxos.show_platform import ShowVersion
from genie.libs.parser.nxos.show_platform import ShowModule
from genie.libs.parser.nxos.show_platform import ShowInventory
from pprint import pformat as pf

logger = create_logger(__name__)


class MDSDeviceHandler(BaseDeviceHandler, abc.ABC):

    def __init__(self, ip: str, credentials: dict):
        super().__init__(ip, credentials)
        logger.debug(f"Instantiating MDS device handler for {ip}")
        self.handler = self.connect()
        self.sys = ShowVersion(self.handler).parse()
        self.inv = ShowInventory(self.handler).parse()

    def connect(self):
        logger.debug(f"Connecting to MDS device {self.ip}")
        handler = Connection(hostname=self.ip,
                             os='nxos',
                             platform='mds',
                             start=[f'ssh -p 22 {self.username}@{self.ip}'],
                             learn_hostname=True,
                             credentials=self.credentials,
                             login_creds=[x for x in self.credentials.keys()],
                             mit=True)
        handler.connect()
        logger.info(f"Successfully connected to {self.ip}")
        self.handler = handler
        return handler

    def disconnect(self):
        logger.debug(f"Disconnecting from MDS device {self.ip}")
        self.handler = None
        logger.info(f"Disconnected from {self.ip}")

    def execute(self, command: str | list, *args, **kwargs) -> str:
        if isinstance(command, list):
            logger.debug(f'Executing multiple commands "{command}" on {self.ip}')
            results = []
            for cmd in command:
                results.append(self.execute(cmd, *args, **kwargs))
        else:
            logger.debug(f'Executing command "{command}" on {self.ip}')
            results = self.handler.execute(command, *args, **kwargs)
            if "Unknown command" in results:
                raise Exception(f"Unknown command on device {self.ip}: {command}")
            if not results:
                logger.warning(f"Command returned no data on device {self.ip}: {command}")
            logger.debug(f'Command {command} executed successfully on {self.ip}')
            logger.debug(f'Results: {results}')
        return results

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
            },
            "modules": self.get_modules(),
            "inventory_items": self.get_inventory_items(),
            "primary_ip4": self.get_primary_ip4(),
            "interfaces": self.get_interfaces(),
            "ip_addresses": self.get_ip_addresses(),
        }
        return results

    def get_serial(self):
        try:
            serial = self.inv['name']['Chassis']['serial_number']
        except KeyError:
            serial = self.sys['platform']['hardware']['processor_board_id']
        return serial

    def get_model(self):
        try:
            model = self.sys['platform']['hardware']['model']
        except KeyError:
            model = self.inv['name']['Chassis']['pid']
        return model

    def get_bios_version(self):
        return self.sys['platform']['software']['bios_version']

    def get_platform_version(self):
        return self.sys['platform']['software']['system_version']

    def get_modules(self):
        show_module = ShowModule(self.handler).parse()
        modules = []
        for module_name, module_data in show_module['slot']['rp'].items():
            for card_name, card_data in module_data.items():
                modules.append({
                    "manufacturer": "Cisco",
                    "module_type": card_data['model'],
                    "module_bay": f"SLOT-RP-{module_name}",
                    "serial": card_data.get('serial_number', "N/A"),
                    "custom_fields": {
                        "fw_version": "N/A",
                    },
                })
        return modules

    def get_inventory_items(self):
        results = []
        for key, data in self.inv['name'].items():
            results.append({
                "name": key,
                "role": "Switch Component",
                "manufacturer": "Cisco",
                "part_number": data['pid'],
                "serial": data['serial_number'],
                "custom_fields": {
                    "fw_version": data.get('vid', 'N/A'),
                },
            })

    def get_primary_ip4(self):
        cmd: str = self.execute('show ip interface')
        parsed = re.match(r'\s*Internet\saddress\sis\s(.*)', cmd)
        if parsed is not None:
            return parsed.group(1)
        else:
            return None

    def get_interfaces(self):
        """
        Get fibre channel adapter information from device and return as list with the following format:
        - name
        - type
        - description
        - firmware
        - speed
        - wwpn
        :return:
        """
        results = []
        logger.debug(f'Getting interfaces from {self.ip}')
        sh_interface = self.execute('show interface')
        interfaces = fsm_parser(sh_interface, fsm_template=fsm_template_mds_show_interface_fc)
        for interface in interfaces:
            results.append({
                "name": interface['Interface'],
                "description": interface['Description'],
                "speed": int(int(interface['Speed']) * 1000) if interface['Speed'] else 1000,
                "wwn": interface['WWN'],
                "type": f"{interface['Speed']}gfc-sfpp" if interface["Speed"] else f"other"
            })
        interfaces = fsm_parser(sh_interface, fsm_template=fsm_template_mds_show_interface_mgmt)
        for interface in interfaces:
            results.append({
                "name": interface['Interface'],
                "description": interface['Description'],
                "mac_address": interface['MAC'],
                "speed": 1000,
                "mtu": int(interface['MTU']),
                "type": "1000base-t"
            })
        logger.debug(f'Interface data for {self.ip}: {pf(results)}')
        return results

    def get_ip_addresses(self):
        """
        Get ip addresses from device and return as list with the following format:
        - interface
        - ip
        - mask
        :return:
        """
        results = []
        logger.debug(f'Getting ip addresses from {self.ip}')
        interfaces = fsm_parser(self.execute('show interface'), fsm_template=fsm_template_mds_show_interface_mgmt)
        for interface in interfaces:
            results.append({
                "assigned_object": interface['Interface'],
                "assigned_object_type": "dcim.interface",
                "address": ipaddress.ip_interface(f"{interface['IP']}").exploded,
                "status": "active"
            })
        logger.debug(f'IP Interface data for {self.ip}: {pf(results)}')
        return results
