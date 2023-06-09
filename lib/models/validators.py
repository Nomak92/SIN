import ipaddress
import json
import logging
import os
import macaddress
from pydantic import BaseModel, validator
from dotenv import load_dotenv
from lib.clients.netbox import NetboxClient

logger = logging.getLogger()


def optional_value(value):
    if not value:
        return None
    return value


def must_have_value(value):
    if not value:
        raise ValueError(f"must not be empty")
    return value


def must_be_positive(value):
    if value is None:
        return value
    if value <= 0:
        raise ValueError(f'must be positive')
    return value


def manufacturer_validator(value):
    if value not in ['Cisco', 'Intel', 'Emulex', 'Samsung', 'Hynix', 'Micron', 'Qimonda', 'LSI Logic', 'Cypress',
                     'Broadcom', "Toshiba", 'Unknown']:
        raise ValueError(f'must be a valid manufacturer: {value}')
    return value


class NetboxInterface(BaseModel):
    """
    class for Netbox interfaces
    """
    name: str
    type: str
    mac_address: str | None = None
    mtu: int | None = None
    speed: int = 1000
    duplex: str = 'full'
    description: str | None = None
    wwn: str | None = None

    _validate_name = validator('name', allow_reuse=True)(must_have_value)

    @validator('type')
    def type_must_be_valid(cls, v):
        if v not in ["virtual", "lag", "100base-tx", "1000base-t", "2.5gbase-t", "5gbase-t", "10gbase-t", "10gbase-cx4",
                     "1000base-x-gbic", "1000base-x-sfp", "10gbase-x-sfpp", "10gbase-x-xfp", "10gbase-x-xenpak",
                     "10gbase-x-x2", "25gbase-x-sfp28", "40gbase-x-qsfpp", "50gbase-x-sfp28", "100gbase-x-cfp",
                     "100gbase-x-cfp2", "200gbase-x-cfp2", "100gbase-x-cfp4", "100gbase-x-cpak", "100gbase-x-qsfp28",
                     "200gbase-x-qsfp56", "400gbase-x-qsfpdd", "400gbase-x-osfp", "ieee802.11a", "ieee802.11g",
                     "ieee802.11n", "ieee802.11ac", "ieee802.11ad", "ieee802.11ax", "gsm", "cdma", "lte", "sonet-oc3",
                     "sonet-oc12", "sonet-oc48", "sonet-oc192", "sonet-oc768", "sonet-oc1920", "sonet-oc3840",
                     "1gfc-sfp", "2gfc-sfp", "4gfc-sfp", "8gfc-sfpp", "16gfc-sfpp", "32gfc-sfp28", "128gfc-sfp28",
                     "infiniband-sdr", "infiniband-ddr", "infiniband-qdr", "infiniband-fdr10", "infiniband-fdr",
                     "infiniband-edr", "infiniband-hdr", "infiniband-ndr", "infiniband-xdr", "t1", "e1", "t3", "e3",
                     "cisco-stackwise", "cisco-stackwise-plus", "cisco-flexstack", "cisco-flexstack-plus",
                     "juniper-vcp", "extreme-summitstack", "extreme-summitstack-128", "extreme-summitstack-256",
                     "extreme-summitstack-512", "other"]:
            raise ValueError(f'must be a valid interface type: {v}')
        return v

    @validator('mac_address')
    def mac_must_be_valid(cls, v):
        if v is None:
            return ""
        try:
            mac = macaddress.parse(v, macaddress.EUI48)
            return str(mac).replace('-', ':')
        except ValueError:
            raise ValueError(f'must be a valid mac address: {v}')

    _validate_mtu = validator('mtu', allow_reuse=True)(must_be_positive)
    _validate_speed = validator('speed', allow_reuse=True)(must_be_positive)

    @validator('duplex')
    def duplex_must_be_valid(cls, v):
        if v.lower() not in ['full', 'half']:
            raise ValueError(f'must be full or half: {v}')
        return v.lower()

    @validator('description')
    def description_must_be_valid(cls, v):
        if v is None:
            return v
        if len(v) > 200:
            raise ValueError(f'must be less than 200 characters: {v}')
        return v

    @validator('wwn')
    def wwn_must_be_valid(cls, v):
        if not v:
            return None
        try:
            wwn = macaddress.parse(v, macaddress.EUI64)
            return str(wwn).replace('-', ':')
        except ValueError:
            raise ValueError(f'must be a valid wwn: {v}')


class NetboxInventoryItem(BaseModel):
    """
    class for Netbox inventory item
    """
    name: str
    manufacturer: str
    part_id: str
    role: str
    custom_fields: dict
    serial: str = "N/A"

    _validate_name = validator('name', allow_reuse=True)(must_have_value)
    _validate_manufacturer = validator('manufacturer', allow_reuse=True)(manufacturer_validator)
    _validate_part_id = validator('part_id', allow_reuse=True)(must_have_value)

    @validator('role')
    def role_must_be_valid(cls, value):
        if value not in ["CPU", "Memory", "Flash", "SSD", "HDD"]:
            raise ValueError(f'role is not valid: {value}')
        return value

    @validator('custom_fields')
    def custom_fields_must_be_valid(cls, value):
        if value is None:
            return {}
        for key in value.copy():
            if key not in ["fw_version", "size", "speed"]:
                value.pop(key)
        return value

    @validator('serial')
    def serial_must_be_valid(cls, value):
        if value is None:
            return "N/A"
        if len(value) > 100:
            raise ValueError(f'serial must be less than 100 characters: {value}')
        return value


class NetboxModule(BaseModel):
    """
    class for Netbox modules
    """
    module_type: str
    module_bay: str
    manufacturer: str
    serial: str = "N/A"
    custom_fields: dict | None = None

    _validate_module_type = validator('module_type', allow_reuse=True)(must_have_value)
    _validate_module_bay = validator('module_bay', allow_reuse=True)(must_have_value)
    _validate_manufacturer = validator('manufacturer', allow_reuse=True)(manufacturer_validator)

    @validator('serial')
    def serial_must_be_valid(cls, value):
        if value is None:
            return "N/A"
        if len(value) > 100:
            raise ValueError(f'serial must be less than 100 characters: {value}')
        return value

    @validator('custom_fields')
    def custom_fields_must_be_valid(cls, value):
        if value is None:
            return {}
        for key in value.copy():
            if key not in ["fw_version"]:
                value.pop(key)
        return value


class NetboxIPAddress(BaseModel):
    """
    class for Netbox IP addresses
    """
    address: str
    status: str = 'active'
    assigned_object: str
    assigned_object_type: str

    @validator('address')
    def address_must_be_valid(cls, value):
        try:
            ipaddress.ip_interface(value)
            return value
        except ValueError:
            raise ValueError(f'must be a valid IP address: {value}')

    @validator('status')
    def status_must_be_valid(cls, value):
        if value not in ["active", "reserved", "deprecated"]:
            raise ValueError(f'must be a valid status: {value}')
        return value

    @validator('assigned_object_type')
    def assigned_object_type_must_be_valid(cls, value):
        if value not in ["dcim.interface"]:
            raise ValueError(f'must be a valid assigned_object_type: {value}')
        return value

    _validate_assigned_object = validator('assigned_object', allow_reuse=True)(must_have_value)


class NetboxDevice(BaseModel):
    name: str
    device_type: str | int
    device_role: str | int
    site: str | int
    platform: str | int
    serial: str
    custom_fields: dict
    tenant: str | int
    cluster: str | int | None = None
    location: str | int | None = None
    primary_ip4: str | int | None = None
    interfaces: list | None = None
    modules: list | None = None
    inventory_items: list | None = None
    ip_addresses: list | None = None
    tags: str | list | None
    rack: str | int | None = None
    local_context_data: str | dict | None = None
    position: int | None = None
    face: str | None = None
    primary_ip6: str | None = None
    asset_tag: str | None = None
    status: str | None = 'active'
    comments: str | None = ""
    virtual_chassis: str | int | None = None
    vc_position: int | None = None
    vc_priority: int | None = None
    airflow: str | None = None
    devices: list | None = None
    slot_id: int | None = None

    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def handler(cls) -> NetboxClient:
        load_dotenv()
        return NetboxClient(os.getenv('NETBOX_URL'), os.getenv('NETBOX_TOKEN'))

    _validate_name = validator('name', allow_reuse=True)(must_have_value)

    @validator('device_type')
    def validate_device_type(cls, param: str) -> int:
        result = cls.handler().get_device_type(param)
        if not result:
            result = cls.handler().get_device_type_by_part_id(param)
        assert result, f"Device type {param} not found"
        return result

    @validator('device_role')
    def validate_device_role(cls, param: str) -> int:
        result = cls.handler().get_device_role(param)
        assert result, f"Device role {param} not found"
        return result

    @validator('site')
    def validate_site(cls, param: str) -> int:
        result = cls.handler().get_site(param)
        assert result, f"Site {param} not found"
        return result

    @validator('platform')
    def validate_platform(cls, param: str) -> int:
        result = cls.handler().get_platform(param)
        assert result, f"Platform {param} not found"
        return result

    _validate_serial = validator('serial', allow_reuse=True)(must_have_value)

    @validator('custom_fields')
    def validate_custom_fields(cls, param: dict) -> dict:
        errors = []
        # custom fields requiring a value
        for key in ["management_ip", "management_username", "management_password", "os_ip", "os_username",
                    "os_password", "fw_version", "bios_version", "cpu_cores", "memory_gb"]:
            if key in param.keys():
                if not param[key]:
                    errors.append(f"custom field {key} must not be empty")
                    continue
        if "memory_gb" in param.keys():
            try:
                param["memory_gb"] = int(param["memory_gb"])
            except ValueError:
                errors.append(f"custom field memory_gb must be an integer")
        if errors:
            raise ValueError(errors)
        return param

    @validator('cluster')
    def validate_cluster(cls, param: str) -> int | None:
        if not param:
            return None
        result = cls.handler().get_cluster(param)
        assert result, f"Cluster {param} not found"
        return result

    @validator('tenant')
    def validate_tenant(cls, param: str) -> int:
        result = cls.handler().get_tenant(param)
        assert result, f"Tenant {param} not found"
        return result

    @validator('location')
    def validate_location(cls, param: str) -> int | None:
        if not param:
            return None
        result = cls.handler().get_location(param)
        assert result, f"Location {param} not found"
        return result

    @validator('primary_ip4')
    def validate_primary_ip4(cls, param: str) -> int | None:
        if not param:
            return None
        try:
            result = cls.handler().get_ip_address(param).id
        except AttributeError:
            result = cls.handler().create_ip_address(param).id
        assert result, f"IP address {param} not found"
        return result

    @validator('interfaces')
    def validate_interfaces(cls, param: list) -> list[NetboxInterface] | None:
        if not param:
            return None
        results = []
        for interface in param:
            assert isinstance(interface, dict), f"Interface {interface} must be a dict"
            results.append(NetboxInterface(**interface))
        return results

    @validator('modules')
    def validate_modules(cls, param: list) -> list[NetboxModule] | None:
        if not param:
            return None
        results = []
        for module in param:
            assert isinstance(module, dict), f"Module {module} must be a dict"
            results.append(NetboxModule(**module))
        return results

    @validator('inventory_items')
    def validate_inventory_items(cls, param: list) -> list[NetboxInventoryItem] | None:
        if not param:
            return None
        results = []
        for inventory_item in param:
            assert isinstance(inventory_item, dict), f"Inventory item {inventory_item} must be a dict"
            results.append(NetboxInventoryItem(**inventory_item))
        return results

    @validator('ip_addresses')
    def validate_ip_addresses(cls, param: list) -> list[NetboxIPAddress] | None:
        if not param:
            return None
        results = []
        for ip_address in param:
            assert isinstance(ip_address, dict), f"IP address {ip_address} must be a dict"
            results.append(NetboxIPAddress(**ip_address))
        return results

    @validator('rack')
    def validate_rack(cls, param: str) -> int | None:
        if param:
            return cls.handler().get_rack(param)
        return None

    @validator('local_context_data')
    def validate_local_context_data(cls, param: str) -> dict | None:
        if param:
            try:
                return json.loads(param)
            except json.JSONDecodeError:
                raise ValueError(f"local_context_data must be a valid JSON string")
        return None

    _validate_position = validator('position', allow_reuse=True)(must_be_positive)

    @validator('face')
    def validate_face(cls, param: str) -> str | None:
        if param:
            if param not in ["front", "rear"]:
                raise ValueError(f"face must be either front or rear")
            return param
        return None

    @validator('primary_ip6')
    def validate_primary_ip6(cls, param: str) -> int | None:
        if param:
            return cls.handler().get_ip_address(param).id
        return None

    _validate_asset_tag = validator('asset_tag', allow_reuse=True)(optional_value)

    @validator('status')
    def validate_status(cls, param: str) -> str | None:
        if param:
            if param not in ["active", "planned", "staged", "failed", "inventory", "decommissioning", "offline"]:
                raise ValueError("status must be either active, planned, staged, failed, inventory, decommissioning "
                                 "or offline")
            return param
        return 'active'

    @validator('comments')
    def validate_comments(cls, param: str) -> str:
        if param:
            return param
        return ''

    @validator('tags')
    def validate_tags(cls, param: str | None) -> list:
        if not param:
            return []
        return [tag.strip() for tag in param.split(",")]

    @validator('virtual_chassis')
    def validate_virtual_chassis(cls, param: str) -> int | None:
        if param:
            return cls.handler().get_virtual_chassis(param)
        return None

    _validate_vc_position = validator('vc_position', allow_reuse=True)(must_be_positive)
    _validate_vc_priority = validator('vc_priority', allow_reuse=True)(must_be_positive)

    @validator('airflow')
    def validate_airflow(cls, param: str) -> str | None:
        if param:
            if param not in ["front-to-rear", "rear-to-front", "left-to-right", "right-to-left", "side-to-rear",
                             "passive", "mixed"]:
                raise ValueError("airflow must be one of front-to-rear, rear-to-front, left-to-right, right-to-left, "
                                 "side-to-rear, passive, mixed")
            return param
        return None

    @validator('devices')
    def validate_devices(cls, param: list) -> list["NetboxDevice"] | None:
        if not param:
            return None
        results = []
        for device in param:
            assert isinstance(device, dict), f"Device {device} must be a dict"
            results.append(NetboxDevice(**device))
        return results

    @validator('slot_id')
    def validate_slot_id(cls, param: int | None) -> int | None:
        if param:
            if param < 1:
                raise ValueError("slot_id must be greater than 0")
            return param
        return None


class NetboxVirtualChassis(BaseModel):
    name: str
    members: list[NetboxDevice]

    _validate_name = validator('name', allow_reuse=True)(must_have_value)

    @validator('members')
    def validate_members(cls, param: list) -> list[NetboxDevice]:
        for member in param:
            assert isinstance(member, NetboxDevice), f"Member {member} must be a NetboxDevice object"
        return param
