"""Thin wrapper around the Netbox API for the data this tool reads."""

import functools
from pprint import pformat

import pynetbox


class NetboxClient:
    """Utils for Netbox stuff."""

    def __init__(self, logger, configobj):
        self.log = logger
        self.config = configobj

        self.log.debug("Logging into Netbox")
        self.api = pynetbox.api(
            self.config.netboxurl,
            token=self.config.netboxtoken,
            threading=True,
        )

        self.vms = self.api.virtualization.virtual_machines
        self.devices = self.api.dcim.devices

    ####################
    # Virtual Machines #
    ####################
    @functools.cache
    def get_vms_all(self) -> list:
        """Get all VMs from Netbox"""
        self.log.debug("Get all VMs from Netbox")
        return list(self.vms.all())

    @functools.cache
    def get_vms_active_soc_server(self) -> list:
        self.log.debug("Get active SOC server VMs")
        vms = self.get_vms_all()
        return list(vms.filter(role="server", tenant="soc", status="active"))

    ####################
    # Physical Devices #
    ####################
    @functools.cache
    def get_devices_all(self):
        self.log.debug("Get all devices")
        return self.devices.all()

    @functools.cache
    def get_devices_active_soc_server(self) -> list:
        self.log.debug("Get Active SOC server devices")
        return list(self.devices.filter(role="server", tenant="soc", status="active"))

    @functools.cache
    def get_devices_juniper_noc(self) -> list:
        self.log.debug("Get Active/Staged NOC Junipers")
        # https://netbox.noc.sonic.net/dcim/devices/?status=active&status=staged&manufacturer_id=5&tenant_id=5
        return list(self.devices.filter(manufacturer="juniper", tenant=["noc"], status=["active", "staged"]))

    ##########################
    # Hosts == VMs + Devices #
    ##########################
    @functools.cache
    def get_hosts_all(self) -> list:
        self.log.debug("Get all hosts")
        vms = self.get_vms_all()
        devices = self.get_devices_all()
        return list(vms) + list(devices)

    @functools.cache
    def get_hosts_active_soc_server(self) -> list:
        self.log.debug("Get all active soc server hosts")
        vms = self.get_vms_active_soc_server()
        devices = self.get_devices_active_soc_server()
        return list(vms) + list(devices)

    #####################
    # Organization Info #
    #####################

    @functools.cache
    def get_regions_all(self):
        self.log.debug("Get all regions")
        return self.api.dcim.regions.all()

    @functools.cache
    def get_sites_all(self):
        self.log.debug("Get all sites")
        return self.api.dcim.sites.all()

    @functools.cache
    def get_sites_smart_filter(self) -> list:
        self.log.debug("Get sites that have at least 1 device")
        sites = []
        for site in self.get_sites_all():
            if site.device_count >= 1:
                sites.append(site)
        return sites

    @functools.cache
    def get_cluster_by_id(self, id):
        """This basically just exists for caching"""
        self.log.debug(id)
        return self.api.virtualization.clusters.get(id)

    ##########################
    # Individual Server Info #
    ##########################

    @functools.cache
    def get_server_services_all(self, server):
        self.log.debug(server)
        server_id = server.id
        if self.is_virtual(server):
            services = self.api.ipam.services.filter(virtual_machine_id=server_id)
        else:
            services = self.api.ipam.services.filter(device_id=server_id)

        return list(services)

    @functools.cache
    def get_server_services_offnet(self, server):
        self.log.debug(server)
        server_id = server.id
        if self.is_virtual(server):
            services = self.api.ipam.services.filter(tag="offnet-ports-open", virtual_machine_id=server_id)
        else:
            services = self.api.ipam.services.filter(tag="offnet-ports-open", device_id=server_id)

        return list(services)

    @functools.cache
    def is_physical(self, server) -> bool:
        self.log.debug(server)
        if "device_type" in dict(server):
            return True
        else:
            return False

    @functools.cache
    def is_virtual(self, server) -> bool:
        self.log.debug(server)
        if "memory" in dict(server):
            return True
        else:
            return False

    @functools.cache
    def virt_type(self, server) -> bool:
        self.log.debug(server)
        if self.config.verbose >= 4:
            self.log.debug(pformat(dict(server)))
        if server.cluster:
            self.log.debug("Has a cluster")
            self.log.debug(server.cluster)
            if self.config.verbose >= 4:
                self.log.debug(pformat(dict(server.cluster)))
            cluster = self.get_cluster_by_id(server.cluster["id"])
            self.log.debug(f"resulting cluster: {pformat(cluster)}")
            # server.cluster.full_details()
            if not cluster or not cluster.type:
                self.log.debug("No cluster or cluster.type")
                return False

            self.log.debug(pformat(dict(cluster)))

            type = cluster.type["display"]
            if type and type.startswith("VMware"):
                type = "VMware"
            return type
        else:
            self.log.debug("No server.cluster")
            return False

    @functools.cache
    def get_ipmi_ip(self, server) -> str:
        ipmask = False

        if self.is_virtual(server):
            return False

        self.log.debug(f"Server: {server}")
        if self.config.verbose >= 4:
            self.log.debug(pformat(dict(server)))
        if server.oob_ip and server.oob_ip["address"]:
            self.log.debug("Has oob_ip")
            ipmask = server.oob_ip["address"]
        else:
            self.log.debug("No oob_ip")
            ipmi_interface = self.api.dcim.interfaces.get(name="IPMI", device_id=server.id)
            if ipmi_interface:
                self.log.debug(f"IPMI interface: {ipmi_interface}")
                ipmi_ip = self.api.ipam.ip_addresses.get(interface_id=ipmi_interface.id)
                if ipmi_ip:
                    ipmask = str(ipmi_ip)
                self.log.debug(f"IP from IPMI interface: {ipmask}")
            else:
                self.log.debug("No IPMI interface")

        if ipmask:
            ip = ipmask.split("/")[0]
            self.log.info(f"IPMI IP for {server} is {ip}")
            return ip
        else:
            return False
