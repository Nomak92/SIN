import abc
import csv
import ipaddress
import logging
from lib.clients.connectors.base import BaseDeviceHandler
from unicon.plugins.linux import LinuxConnection
from pprint import pformat as pf

logger = logging.getLogger()


class EsxiDeviceHandler(BaseDeviceHandler, abc.ABC):

    def __init__(self, ip: str, credentials: dict):
        super().__init__(ip, credentials)
        self.handler = self.connect()

    def connect(self):
        logger.debug(f"Connecting to device {self.ip}")
        if self.handler is None:
            logger.debug(f"Creating connection handler for {self.ip}")
            handler = LinuxConnection(hostname=self.ip,
                                      os='linux',
                                      start=[f'ssh -p 22 {self.credentials["default"]["username"]}@{self.ip}'],
                                      learn_hostname=True,
                                      credentials=self.credentials,
                                      login_creds=[x for x in self.credentials.keys()],
                                      mit=True)
            handler.connect()
            logger.info(f"Successfully connected to {self.ip}")
            return handler
        if not self.handler.is_connected:
            self.handler.connect()
            logger.info(f"Successfully connected to {self.ip}")
        return self.handler

    def disconnect(self):
        if self.handler.is_connected:
            self.handler.disconnect()
            logger.info(f"Disconnected from {self.ip}")
        if self.handler is not None:
            self.handler.disconnect()
            logger.info(f"Disconnected from {self.ip}")

    def execute(self, command: str):
        logger.debug(f'Executing command "{command}" on {self.ip}')
        if not self.handler.is_connected:
            self.handler.connect()
        results = self.handler.execute(command, prompt_recovery=True, timeout=5)
        if "Unknown command" in results:
            raise Exception(f"Unknown command on device {self.ip}: {command}")
        if not results:
            logger.warning(f"Command returned no data on device {self.ip}: {command}")
        logger.debug(f'Command {command} executed successfully on {self.ip}')
        logger.debug(f'Results: {pf(results)}')
        return results

    def discover(self):
        if not self.handler.is_connected:
            self.handler.connect()
        results = {
            "interfaces": self.get_interfaces(),
            "ip_addresses": self.get_ip_addresses(),
        }
        logger.debug(f'Discovered data for {self.ip}: {pf(results)}')
        self.disconnect()
        return results

    def exec_and_parse_str(self, command: str) -> str:
        if not self.handler.is_connected:
            self.handler.connect()
        command_result = self.execute(command)
        logger.debug(f'data from command "{command}" to be parsed: {pf(command_result)}')
        return command_result.splitlines()[0].split(':')[1].strip()

    def exec_and_parse_csv(self, command: str) -> list[dict]:
        if not self.handler.is_connected:
            self.handler.connect()
        command_result = self.execute(command)
        if not command_result:
            logger.warning(f'No data returned from command "{command}"')
            return []
        csv_command = csv.reader(command_result.splitlines(), delimiter=',')
        headers = [x for x in next(csv_command) if x != '']
        objects = [dict(zip(headers, interface)) for interface in csv_command]
        logger.debug(f'Parsed data from command "{command}": {pf(objects)}')
        return objects

    def get_ethernet_interfaces(self) -> list[dict]:
        """
        Get interfaces from device and return as list with the following format:
        - name
        - type
        - description
        - mac
        - MTU
        - speed
        - duplex
        :return:
        """
        results = []
        logger.debug(f'Getting ethernet interfaces from {self.ip}')
        interfaces = self.exec_and_parse_csv("esxcli --formatter=csv network nic list")
        for interface in interfaces:
            results.append({
                "name": interface['Name'],
                "description": interface['Description'],
                "mac_address": interface['MACAddress'],
                "mtu": int(interface['MTU']),
                "speed": int(interface['Speed']) if int(interface["Speed"]) != 0 else 1000,
                "duplex": interface['Duplex'].lower(),
                "type": "10gbase-x-sfpp" if int(interface["Speed"]) == 10000 else "1000base-t"
            })

        logger.debug(f'Ethernet Interface data for {self.ip}: {pf(results)}')
        return results

    def get_interfaces(self) -> list[dict]:
        results = []
        logger.debug(f'Getting interfaces from {self.ip}')
        results.extend(self.get_ethernet_interfaces())
        results.extend(self.get_ip_interfaces())
        results.extend(self.get_fc_interfaces())
        logger.debug(f'All Interfaces discovered for {self.ip}: {pf(results)}')
        return results

    def get_ip_interfaces(self) -> list[dict]:
        """
        Get ip interfaces from device and return as list with the following format:
        - name
        - type
        - description
        - mac
        - MTU
        :return:
        """
        results = []
        logger.debug(f'Getting ip interfaces from {self.ip}')
        interfaces = self.exec_and_parse_csv("esxcli --formatter=csv network ip interface list")
        for interface in interfaces:
            results.append({
                "name": interface['Name'],
                "description": interface['Portgroup'],
                "mac_address": interface['MACAddress'],
                "mtu": int(interface['MTU']),
                "type": "virtual"
            })
        logger.debug(f'IP Interface data for {self.ip}: {pf(results)}')
        return results

    def get_ip_addresses(self) -> list[dict]:
        """
        Get ip addresses from device and return as list with the following format:
        - interface
        - ip
        - mask
        :return:
        """
        results = []
        logger.debug(f'Getting ip addresses from {self.ip}')
        interfaces = self.exec_and_parse_csv("esxcli --formatter=csv network ip interface ipv4 get")
        for interface in interfaces:
            results.append({
                "assigned_object": interface['Name'],
                "assigned_object_type": "dcim.interface",
                "address": ipaddress.ip_interface(f"{interface['IPv4Address']}/{interface['IPv4Netmask']}").exploded,
                "status": "active"
            })
        logger.debug(f'IP Interface data for {self.ip}: {pf(results)}')
        return results

    def get_fc_interfaces(self) -> list[dict]:
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
        logger.debug(f'Getting fibre channel interfaces from {self.ip}')
        interfaces = self.exec_and_parse_csv("esxcli --formatter=csv storage san fc list")
        for interface in interfaces:
            results.append({
                "name": interface['Adapter'],
                "description": interface['ModelDescription'],
                "speed": int(int(interface['Speed']) * 1000) if int(interface['Speed']) != 0 else 16000,
                "wwn": interface['PortName'],
                "type": f"{interface['Speed']}gfc-sfpp" if int(interface["Speed"]) != 0 else f"16gfc-sfpp"
            })
        logger.debug(f'FC Interface data for {self.ip}: {pf(results)}')
        return results
