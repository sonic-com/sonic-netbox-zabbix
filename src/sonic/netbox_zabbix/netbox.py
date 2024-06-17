import functools
from pprint import pformat

import pynetbox


class SonicNetboxZabbix_Netbox:
    """
    Utils for Netbox stuff
    """

    log = False
    config = False

    def __init__(self, logger, configobj):
        global log
        global config

        self.log = logger
        self.config = configobj

        log = self.log
        config = self.config

        log.debug("Logging into Netbox")
        self.api = pynetbox.api(
            config.netboxurl,
            token=config.netboxtoken,
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
        return list(self.vms.all())

    @functools.cache
    def get_vms_active_soc_server(self) -> list:
        vms = self.get_vms_all()
        return list(self.vms.filter(role="server", tenant="soc", status="active"))

    ####################
    # Physical Devices #
    ####################
    @functools.cache
    def get_devices_all(self):
        return self.devices.all()

    @functools.cache
    def get_devices_active_soc_server(self) -> list:
        return list(self.devices.filter(role="server", tenant="soc", status="active"))

    ##########################
    # Hosts == VMs + Devices #
    ##########################
    @functools.cache
    def get_hosts_all(self) -> list:
        vms = self.get_vms_all()
        devices = self.get_devices_all()
        return list(vms) + list(devices)

    @functools.cache
    def get_hosts_active_soc_server(self) -> list:
        vms = self.get_vms_active_soc_server()
        devices = self.get_devices_active_soc_server()
        return list(vms) + list(devices)

    #####################
    # Organization Info #
    #####################

    @functools.cache
    def get_regions_all(self):
        return self.api.dcim.regions.all()

    @functools.cache
    def get_sites_all(self):
        return self.api.dcim.sites.all()

    @functools.cache
    def get_sites_smart_filter(self) -> list:
        sites = []
        for site in self.get_sites_all():
            if site.device_count >= 1:
                sites.append(site)
        return sites

    @functools.cache
    def is_physical(self, server) -> bool:
        if "device_type" in dict(server):
            return True
        else:
            return False

    @functools.cache
    def is_virtual(self, server) -> bool:
        if "memory" in dict(server):
            return True
        else:
            return False

    @functools.cache
    def get_cluster_by_id(self, id):
        """This basically just exists for caching"""
        return self.api.virtualization.cluster.get(id)

    @functools.cache
    def virt_type(self, server) -> bool:
        if self.is_physical(server):
            return False
        elif server.cluster:
            cluster = self.get_cluster_by_id(server.cluster["id"])
            # server.cluster.full_details()
            if not cluster or not cluster.type:
                return False
            type = cluster.type["display"]
            if type.startswith("VMware"):
                type = "VMware"
            return type
        else:
            return "UNKNOWN"
