import functools

import pynetbox


class SonicNetboxZabbix_Netbox:
    """
    Utils for Netbox stuff
    """

    def __init__(self, logger, config):
        self.log = logger
        self.config = config

        self.log.info("Logging into Netbox")
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
    def get_vms_all(self):
        """Get all VMs from Netbox"""
        return self.vms.all()

    @functools.cache
    def get_vms_active_soc_server(self):
        vms = self.get_vms_all()
        return self.vms.filter(role="server", tenant="soc", status="active")

    ####################
    # Physical Devices #
    ####################
    @functools.cache
    def get_devices_all(self):
        return self.devices.all()

    @functools.cache
    def get_devices_active_soc_server(self):
        return self.devices.filter(role="server", tenant="soc", status="active")

    ##########################
    # Hosts == VMs + Devices #
    ##########################
    @functools.cache
    def get_hosts_all(self):
        vms = self.get_vms_all()
        devices = self.get_devices_all()
        return list(vms) + list(devices)

    @functools.cache
    def get_hosts_active_soc_server(self):
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
