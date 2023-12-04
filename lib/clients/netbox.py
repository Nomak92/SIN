import logging
import pynetbox
from pynetbox.core.response import Record

logger = logging.getLogger()


class NetboxClient:

    def __init__(self, url: str, token: str):
        logger.debug(f'Creating Netbox client with url {url} and token {token}')
        self.url = url
        self.token = token
        self.api = pynetbox.api(url, token=token)

    def _create_device(self, name: str, device_type: int, device_role: int, site: int, status: str, tenant: int = None,
                       platform: int = None, serial: str = None, asset_tag: str = None, location: int = None,
                       rack: int = None, position: int = None, face: str = None, airflow: str = None,
                       cluster: int = None, virtual_chassis: int = None, vc_position: int = None,
                       vc_priority: int = None, comments: str = None, local_context_data: dict = None,
                       tags: list[str] = None, custom_fields: dict = None) -> Record | None:
        logger.debug(f'Creating device {name}')
        return self.api.dcim.devices.create(name=name, device_type=device_type, role=device_role, site=site,
                                            tenant=tenant, status=status, platform=platform, serial=serial,
                                            asset_tag=asset_tag, location=location, rack=rack, position=position,
                                            face=face, airflow=airflow, cluster=cluster,
                                            virtual_chassis=virtual_chassis, vc_position=vc_position,
                                            vc_priority=vc_priority, comments=comments,
                                            local_context_data=local_context_data, tags=tags,
                                            custom_fields=custom_fields)

    def _create_vm(self, name: str, device: int, cluster: int, status: str, site: int, role: int, tenant: int, platform: int,
                   vcpus: int, memory: int, disk: int, description: str = None, comments: str = None,
                   local_context_data: dict = None, tags: list[str] = None, custom_fields: dict = None) \
            -> Record | None:
        logger.debug(f'Creating VM {name}')
        return self.api.virtualization.virtual_machines.create(name=name, device=device, cluster=cluster, status=status, site=site,
                                                               role=role, tenant=tenant, platform=platform,
                                                               description=description,
                                                               local_context_data=local_context_data, vcpus=vcpus,
                                                               memory=memory, disk=disk, comments=comments, tags=tags,
                                                               custom_fields=custom_fields)

    @staticmethod
    def _update_device(device: Record, name: str, device_type: int, device_role: int, site: int, status: str,
                       tenant: int = None, platform: int = None, serial: str = None, asset_tag: str = None,
                       location: int = None, rack: int = None, position: int = None, face: str = None,
                       airflow: str = None, primary_ip4: int = None, primary_ip6: int = None, cluster: int = None,
                       virtual_chassis: int = None, vc_position: int = None, vc_priority: int = None,
                       comments: str = None, local_context_data: dict = None, tags: list[str] = None,
                       custom_fields: dict = None) -> Record:
        logger.debug(f'Updating device {name}')
        if device is None:
            logger.error(f'Device record must be provided to update device {name}')
            raise ValueError(f'Device record must be provided to update device {name}')
        update_data = {
            'name': name, 'device_type': device_type, 'role': device_role, 'site': site, 'status': status,
            'tenant': tenant, 'platform': platform, 'serial': serial, 'asset_tag': asset_tag, 'location': location,
            'rack': rack, 'position': position, 'face': face, 'airflow': airflow, 'primary_ip4': primary_ip4,
            'primary_ip6': primary_ip6, 'cluster': cluster, 'virtual_chassis': virtual_chassis,
            'vc_position': vc_position, 'vc_priority': vc_priority, 'comments': comments,
            'local_context_data': local_context_data, 'tags': tags, 'custom_fields': custom_fields
        }
        for key in update_data.copy():
            if update_data[key] is None:
                update_data.pop(key)
        logger.debug(f'Updating device {device} with data: {update_data}')
        device.update(update_data)
        return device

    @staticmethod
    def _update_vm(vm: Record, name: str, device: int, cluster: int, status: str, site: int, role: int, tenant: int, platform: int,
                   vcpus: int, memory: int, disk: int, description: str = None, comments: str = None,
                   local_context_data: dict = None, tags: list[str] = None, custom_fields: dict = None) -> Record:
        logger.debug(f'Updating vm {name}')
        if vm is None:
            logger.error(f'VM record must be provided to update device {name}')
            raise ValueError(f'VM record must be provided to update device {name}')
        update_data = {
            'name': name, 'device': device, 'role': role, 'site': site, 'status': status,
            'tenant': tenant, 'platform': platform, 'vcpus': vcpus, 'cluster': cluster, 'memory': memory,
            'disk': disk, 'description': description, 'comments': comments, 'local_context_data': local_context_data,
            'tags': tags, 'custom_fields': custom_fields
        }
        for key in update_data.copy():
            if update_data[key] is None:
                update_data.pop(key)
        logger.debug(f'Updating VM {vm} with data: {update_data}')
        vm.update(update_data)
        return vm

    def create_or_update_device(self, name: str, device_type: int, device_role: int, site: int, status: str,
                                tenant: int = None, platform: int = None, serial: str = None, asset_tag: str = None,
                                location: int = None, rack: int = None, position: int = None, face: str = None,
                                airflow: str = None, primary_ip4: int = None, primary_ip6: int = None,
                                cluster: int = None, virtual_chassis: int = None, vc_position: int = None,
                                vc_priority: int = None, comments: str = None, local_context_data: dict = None,
                                tags: list[str] = None, custom_fields: dict = None, **kwargs) -> Record | None:
        logger.debug(f'Data not sent to Netbox: {kwargs}')
        device = self.get_device(name)
        if device is None:
            logger.debug(f'No device found. Creating device {name}')
            return self._create_device(name=name, device_type=device_type, device_role=device_role, site=site,
                                       tenant=tenant, status=status, platform=platform, serial=serial,
                                       asset_tag=asset_tag, location=location, rack=rack, position=position,
                                       face=face, airflow=airflow, cluster=cluster, virtual_chassis=virtual_chassis,
                                       vc_position=vc_position, vc_priority=vc_priority, comments=comments,
                                       local_context_data=local_context_data, tags=tags, custom_fields=custom_fields)
        else:
            logger.debug(f'Updating device {name} with device id {device.id}')
            return self._update_device(device=device, name=name, device_type=device_type, device_role=device_role,
                                       site=site, tenant=tenant, status=status, platform=platform, serial=serial,
                                       asset_tag=asset_tag, location=location, rack=rack, position=position,
                                       face=face, airflow=airflow, primary_ip4=primary_ip4, primary_ip6=primary_ip6,
                                       cluster=cluster, virtual_chassis=virtual_chassis, vc_position=vc_position,
                                       vc_priority=vc_priority, comments=comments,
                                       local_context_data=local_context_data, tags=tags, custom_fields=custom_fields)

    def create_or_update_vm(self, name: str, device: int, cluster: int, status: str, site: int, role: int, tenant: int,
                            platform: int, vcpus: int, memory: int, disk: int, description: str = None,
                            comments: str = None, local_context_data: dict = None, tags: list[str] = None,
                            custom_fields: dict = None, **kwargs) -> Record | None:
        logger.debug(f'Data not sent to Netbox: {kwargs}')
        vm = self.get_vm(name)
        if vm is None:
            logger.debug(f'No VM found. Creating VM {name}')
            return self._create_vm(name=name, device=device, cluster=cluster, status=status, site=site, role=role, tenant=tenant,
                                   platform=platform, vcpus=vcpus, memory=memory, disk=disk, description=description,
                                   comments=comments, local_context_data=local_context_data, tags=tags,
                                   custom_fields=custom_fields)
        else:
            logger.debug(f'Updating VM {name} with VM id {vm.id}')
            return self._update_vm(vm=vm, name=name, device=device, cluster=cluster, status=status, site=site, role=role,
                                   tenant=tenant, platform=platform, vcpus=vcpus, memory=memory, disk=disk,
                                   description=description, comments=comments, local_context_data=local_context_data,
                                   tags=tags, custom_fields=custom_fields)

    @staticmethod
    def _return_id_or_none(obj: Record | None) -> int | None:
        if obj is not None:
            logger.debug(f'Found object {obj} with id {obj.id}')
            return obj.id
        else:
            logger.debug(f'No object found')
            return None

    def push(self, validated_data: dict) -> list[Record]:
        results = []
        logger.debug(f'Pushing data to Netbox: {validated_data}')
        device = self.create_or_update_device(**validated_data)
        if device is None:
            raise ValueError(f'Failed to create or update device {validated_data["name"]}')
        results.append(device)
        results.extend(self.add_interfaces(device=device.id, interfaces=validated_data['interfaces']))
        results.extend(self.add_ip_addresses(device=device.id, ip_addresses=validated_data['ip_addresses']))
        results.extend(self.add_modules(device=device.id, modules=validated_data['modules']))
        results.extend(self.add_inventory_items(device=device.id, inventory_items=validated_data['inventory_items']))
        return results

    def get_device(self, name: str) -> Record | None:
        return self.api.dcim.devices.get(name=name)

    def get_vm(self, name: str) -> Record | None:
        return self.api.virtualization.virtual_machines.get(name=name)

    def get_device_type(self, param: str) -> int | None:
        return self._return_id_or_none(self.api.dcim.device_types.get(model=param))

    def get_device_role(self, param: str) -> int | None:
        return self._return_id_or_none(self.api.dcim.device_roles.get(name=param))

    def get_site(self, param: str) -> int | None:
        return self._return_id_or_none(self.api.dcim.sites.get(name=param))

    def get_tenant(self, param: str) -> int | None:
        return self._return_id_or_none(self.api.tenancy.tenants.get(name=param))

    def get_platform(self, param: str) -> int | None:
        return self._return_id_or_none(self.api.dcim.platforms.get(name=param))

    def get_location(self, param: str) -> int | None:
        return self._return_id_or_none(self.api.dcim.locations.get(name=param))

    def get_rack(self, param: str) -> int | None:
        return self._return_id_or_none(self.api.dcim.racks.get(name=param))

    def get_cluster(self, param: str) -> int | None:
        return self._return_id_or_none(self.api.virtualization.clusters.get(name=param))

    def get_virtual_chassis(self, param: str) -> int | None:
        return self._return_id_or_none(self.api.dcim.virtual_chassis.get(name=param))

    def get_primary_ip4(self, param: str) -> int | None:
        return self._return_id_or_none(self.api.ipam.ip_addresses.get(address=param))

    def get_primary_ip6(self, param: str) -> int | None:
        return self._return_id_or_none(self.api.ipam.ip_addresses.get(address=param))

    def get_module_bay(self, device: int, name: str) -> int | None:
        return self._return_id_or_none(self.api.dcim.device_bays.get(device=device, name=name))

    def get_module_type(self, param: str) -> int | None:
        return self._return_id_or_none(self.api.dcim.device_types.get(model=param))

    def add_interfaces(self, device: int, interfaces: list[dict]) -> list[Record]:
        results = []
        for interface in interfaces:
            logger.debug(f'Checking if interface {interface["name"]} exists on device {device}')
            interface_obj = self.get_interface(device=device, name=interface['name'])
            if interface_obj is None:
                logger.debug(f'Adding interface {interface["name"]} to device {device}')
                interface_obj = self.api.dcim.interfaces.create(device=device, **interface)
            else:
                logger.debug(f'Updating interface {interface["name"]} on device {device}')
                interface_obj.update(interface)
            if interface_obj is None:
                raise ValueError(f'Failed to create or update interface {interface}')
            results.append(interface_obj)
        return results

    def add_module_bay(self, device: int, name: str) -> int | None:
        logger.info(f'Checking if module bay {name} exists on device {device}')
        module_bay = self.api.dcim.module_bays.get(device_id=device, name=name)
        if module_bay is None:
            logger.info(f'Adding module bay {name} to device {device}')
            module_bay = self.api.dcim.module_bays.create(device=device, name=name)
        else:
            logger.info(f'Module bay {name} already exists on device {device}')
        return self._return_id_or_none(module_bay)

    def add_module_type(self, name: str, manufacturer: int) -> int | None:
        logger.info(f'Checking if module type {name} exists on manufacturer {manufacturer}')
        module_type = self.api.dcim.module_types.get(model=name, manufacturer_id=manufacturer)
        if module_type is None:
            logger.info(f'Adding module type {name}')
            module_type = self.api.dcim.module_types.create(model=name, manufacturer=manufacturer)
        else:
            logger.info(f'Module type {name} already exists')
        return self._return_id_or_none(module_type)

    def add_modules(self, device: int, modules: list[dict]) -> list[Record]:
        results = []
        for module in modules:
            logger.debug(f'Processing module {module}')
            module_bay = self.add_module_bay(device=device, name=module['module_bay'])
            manufacturer = self.get_manufacturer(module['manufacturer'])
            module_type = self.add_module_type(name=module['module_type'], manufacturer=manufacturer)
            module_obj = self.add_module(device=device, module_bay=module_bay, module_type=module_type,
                                         serial=module.get('serial', "N/A"),
                                         custom_fields=module.get('custom_fields', {}))
            if module_obj is None:
                raise ValueError(f'Failed to create module {module}')
            results.append(module_obj)
        return results

    def add_inventory_items(self, device: int, inventory_items: list[dict]) -> list[Record]:
        results = []
        for inventory_item in inventory_items:
            logger.debug(f'Checking if inventory item {inventory_item["name"]} exists on device {device}')
            inventory_item_obj = self.get_inventory_item(device=device, name=inventory_item['name'])
            logger.debug(f'Retrieving inventory role {inventory_item["role"]}')
            role_id = self.get_inventory_role(inventory_item['role'])
            logger.debug(f'Retrieving manufacturer {inventory_item["manufacturer"]}')
            manufacturer_id = self.get_manufacturer(inventory_item['manufacturer'])
            if inventory_item_obj is None:
                logger.debug(f'Adding inventory item {inventory_item} to device {device}')
                inventory_item_obj = self.api.dcim.inventory_items.create(device=device, role=role_id,
                                                                          manufacturer=manufacturer_id,
                                                                          name=inventory_item['name'],
                                                                          part_id=inventory_item['part_id'],
                                                                          serial=inventory_item.get("serial", "N/A"),
                                                                          custom_fields=inventory_item.get(
                                                                              'custom_fields', {}))
            else:
                logger.debug(f'Updating inventory item {inventory_item} on device {device}')
                inventory_item_obj.update({'name': inventory_item["name"], 'role': role_id,
                                           'manufacturer': manufacturer_id, 'part_id': inventory_item['part_id'],
                                           'serial': inventory_item.get("serial", "N/A"),
                                           'custom_fields': inventory_item.get('custom_fields', {})})
            results.append(inventory_item_obj)
        return results

    def add_ip_addresses(self, device: int, ip_addresses: list[dict]) -> list[Record]:
        results = []
        for ip_address in ip_addresses:
            logger.debug('Removing null parameters from IP address dict')
            for key in ip_address.copy():
                if ip_address[key] is None:
                    ip_address.pop(key)
            if ip_address["assigned_object_type"] == "dcim.interface":
                logger.debug(f'Retrieving interface {ip_address["assigned_object"]}')
                assigned_object = self.get_interface(device=device, name=ip_address['assigned_object'])
                if assigned_object is None:
                    raise ValueError(
                        f'{ip_address["assigned_object"]} does not exist as a {ip_address["assigned_object_type"]}'
                        f' object in Netbox on device {device}')
                else:
                    ip_address['assigned_object_id'] = assigned_object.id
            elif ip_address["assigned_object_type"] == "virtualization.vminterface":
                logger.debug(f'Retrieving interface {ip_address["assigned_object"]}')
                assigned_object = self.get_virtual_interface(vm_id=device, name=ip_address['assigned_object'])
                if assigned_object is None:
                    raise ValueError(
                        f'{ip_address["assigned_object"]} does not exist as a {ip_address["assigned_object_type"]}'
                        f' object in Netbox on device {device}')
                else:
                    ip_address['assigned_object_id'] = assigned_object.id
            else:
                raise ValueError(f'Invalid assigned object type {ip_address["assigned_object_type"]}')
            logger.debug(f'Checking if IP address {ip_address["address"]} exists in Netbox')
            ip_address_obj = self.get_ip_address(address=ip_address['address'])
            if ip_address_obj is None:
                logger.debug(f'Adding IP address {ip_address["address"]} to device {device}')
                ip_address_obj = self.api.ipam.ip_addresses.create(**ip_address)
            else:
                logger.debug(f'Updating IP address {ip_address["address"]} on device {device}')
                ip_address_obj.assigned_object_id = assigned_object.id
                ip_address_obj.assigned_object_type = ip_address["assigned_object_type"]
                ip_address_obj.save()
                if "mgmt" in ip_address["assigned_object"].lower():
                    logger.debug(f'Adding MGMT IP address {ip_address["address"]} to Primary IP of device {device}')
                    self.api.dcim.devices.get(id=device).update({"primary_ip4": ip_address_obj.id})
            results.append(ip_address_obj)
        return results

    def get_manufacturer(self, param: str) -> int:
        return self.api.dcim.manufacturers.get(name=param).id

    def add_module(self, device: int, module_bay: int, module_type: int, serial: str, custom_fields: dict) \
            -> Record | None:
        logger.info(f'Checking if module {serial} exists on device {device} in module bay {module_bay}')
        module = self.api.dcim.modules.get(device_id=device, module_bay_id=module_bay)
        if module is None:
            logger.info(f'Adding module {serial} to device {device}')
            module = self.api.dcim.modules.create(device=device, module_bay=module_bay, module_type=module_type,
                                                  serial=serial, custom_fields=custom_fields)
        else:
            logger.info(f'Module {serial} already exists on device {device}. Updating')
            module.update({"serial": serial, "custom_fields": custom_fields})
        return module

    def get_interface(self, device: int, name: str) -> Record | None:
        return self.api.dcim.interfaces.get(device_id=device, name=name)

    def get_virtual_interface(self, vm_id: int, name: str) -> Record | None:
        return self.api.virtualization.interfaces.get(virtual_machine_id=vm_id, name=name)

    def get_inventory_item(self, device: int, name: str) -> Record | None:
        return self.api.dcim.inventory_items.get(device_id=device, name=name)

    def get_ip_address(self, address: str) -> Record | None:
        return self.api.ipam.ip_addresses.get(address=address)

    def get_inventory_role(self, param: str) -> int | None:
        return self._return_id_or_none(self.api.dcim.inventory_item_roles.get(name=param))

    def get_device_type_by_part_id(self, param):
        return self._return_id_or_none(self.api.dcim.device_types.get(part_number=param))

    def add_virtual_chassis(self, name: str) -> Record:
        """
        Creates a virtual chassis in Netbox
        :param name:
        :return:
        """
        logger.debug(f'Checking if virtual chassis {name} exists in Netbox')
        virtual_chassis = self.api.dcim.virtual_chassis.get(name=name)
        if virtual_chassis is None:
            logger.debug(f'Adding virtual chassis {name} to Netbox')
            virtual_chassis = self.api.dcim.virtual_chassis.create(name=name)
        return virtual_chassis

    def add_virtual_chassis_member(self, chassis: dict) -> Record:
        """
        Adds a member to a virtual chassis in Netbox
        :param chassis:
        :return:
        """
        logger.debug(f'Checking if virtual chassis member {chassis["name"]} exists in Netbox')
        virtual_chassis_member = self.get_device(chassis["name"])
        if virtual_chassis_member is None:
            logger.debug(f'Adding virtual chassis member {chassis["name"]} to Netbox')
            virtual_chassis_member = self.create_or_update_device(**chassis)
        return virtual_chassis_member

    def add_device_bay(self, member: Record, server: Record, slot_id: int) -> Record:
        """
        Adds a device to a device's device bay
        :param slot_id:
        :param member:
        :param server:
        :return:
        """
        bay_name = f'SLOT-{slot_id}'
        logger.debug(f'Checking if device bay {bay_name} exists on device {member}')
        device_bay = self.api.dcim.device_bays.get(device_id=member.id, name=bay_name)
        if device_bay is None:
            logger.debug(f'Adding device bay {bay_name} to device {member}')
            device_bay = self.api.dcim.device_bays.create(device=member.id, name=bay_name)
        logger.debug(f'Checking if device {server.name} is in device bay {bay_name} on device {member}')
        if device_bay.installed_device != server.id:
            logger.debug(f'Adding device {member.name} to device bay {bay_name} on device {member}')
            device_bay.update({"installed_device": server.id})
        return device_bay

    def create_ip_address(self, param: str) -> Record:
        logger.info(f'Creating IP address {param} in Netbox')
        return self.api.ipam.ip_addresses.create(address=param)

    def get_assigned_ip_address(self, ip_id: int) -> Record | None:
        ip = self.api.ipam.ip_addresses.get(id=ip_id)
        if ip:
            if ip.assigned_object:
                return ip.assigned_object
        return None

    def add_virtual_interfaces(self, vm: int, interfaces: list[dict]) -> list[Record]:
        results = []
        for interface in interfaces:
            logger.debug(f'Removing no value parameters from interface dict')
            for key in interface.copy():
                if interface[key] is None:
                    interface.pop(key)
            logger.debug(f'Checking if interface {interface["name"]} exists on VM {vm}')
            interface_obj = self.get_virtual_interface(vm_id=vm, name=interface['name'])
            if interface_obj is None:
                logger.debug(f'Adding interface {interface["name"]} to VM {vm}')
                interface_obj = self.api.virtualization.interfaces.create(virtual_machine=vm, **interface)
            else:
                logger.debug(f'Updating interface {interface["name"]} on VM {vm}')
                interface_obj.update(interface)
            if interface_obj is None:
                raise ValueError(f'Failed to create or update interface {interface}')
            results.append(interface_obj)
        return results
