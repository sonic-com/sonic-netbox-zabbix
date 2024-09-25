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
        log.debug("Get all VMs from Netbox")
        return list(self.vms.all())

    @functools.cache
    def get_vms_active_soc_server(self) -> list:
        log.debug("Get active SOC server VMs")
        vms = self.get_vms_all()
        return list(self.vms.filter(role="server", tenant="soc", status="active"))

    ####################
    # Physical Devices #
    ####################
    @functools.cache
    def get_devices_all(self):
        log.debug("Get all devices")
        return self.devices.all()

    @functools.cache
    def get_devices_active_soc_server(self) -> list:
        log.debug("Get Active SOC server devices")
        return list(self.devices.filter(role="server", tenant="soc", status="active"))

    ##########################
    # Hosts == VMs + Devices #
    ##########################
    @functools.cache
    def get_hosts_all(self) -> list:
        log.debug("Get all hosts")
        vms = self.get_vms_all()
        devices = self.get_devices_all()
        return list(vms) + list(devices)

    @functools.cache
    def get_hosts_active_soc_server(self) -> list:
        log.debug("Get all active soc server hosts")
        vms = self.get_vms_active_soc_server()
        devices = self.get_devices_active_soc_server()
        return list(vms) + list(devices)

    #####################
    # Organization Info #
    #####################

    @functools.cache
    def get_regions_all(self):
        log.debug("Get all regions")
        return self.api.dcim.regions.all()

    @functools.cache
    def get_sites_all(self):
        log.debug("Get all sites")
        return self.api.dcim.sites.all()

    @functools.cache
    def get_sites_smart_filter(self) -> list:
        log.debug("Get sites that have at least 1 device")
        sites = []
        for site in self.get_sites_all():
            if site.device_count >= 1:
                sites.append(site)
        return sites

    @functools.cache
    def is_physical(self, server) -> bool:
        log.debug(server)
        if "device_type" in dict(server):
            return True
        else:
            return False

    @functools.cache
    def is_virtual(self, server) -> bool:
        log.debug(server)
        if "memory" in dict(server):
            return True
        else:
            return False

    @functools.cache
    def get_cluster_by_id(self, id):
        """This basically just exists for caching"""
        log.debug(id)
        return self.api.virtualization.clusters.get(id)

    @functools.cache
    def virt_type(self, server) -> bool:
        log.debug(server)
        if config.verbose >= 4:
            log.debug(pformat(dict(server)))
        if server.cluster:
            log.debug("Has a cluster")
            log.debug(server.cluster)
            if config.verbose >= 4:
                log.debug(pformat(dict(server.cluster)))
            cluster = self.get_cluster_by_id(server.cluster["id"])
            log.debug(f"resulting cluster: {pformat(cluster)}")
            # server.cluster.full_details()
            if not cluster or not cluster.type:
                log.debug("No cluster or cluster.type")
                return False

            log.debug(pformat(dict(cluster)))

            type = cluster.type["display"]
            if type and type.startswith("VMware"):
                type = "VMware"
            return type
        else:
            log.debug("No server.cluster")
            return False

    @functools.cache
    def get_ipmi_ip(self, server) -> str:
        ipmask = False

        if self.is_virtual(server):
            return False

        log.debug(f"Server: {server}")
        if config.verbose >= 4:
            log.debug(pformat(dict(server)))
        if server.oob_ip and server.oob_ip["address"]:
            log.debug("Has oob_ip")
            ipmask = server.oob_ip["address"]
        else:
            log.debug("No oob_ip")
            ipmi_interface = self.api.dcim.interfaces.get(name="IPMI", device_id=server.id)
            if ipmi_interface:
                log.debug(f"IPMI interface: {ipmi_interface}")
                ipmi_ip = self.api.ipam.ip_addresses.get(interface_id=ipmi_interface.id)
                if ipmi_ip:
                    ipmask = str(ipmi_ip)
                log.debug(f"IP from IPMI interface: {ipmask}")
            else:
                log.debug("No IPMI interface")

        if ipmask:
            ip = ipmask.split("/")[0]
            log.info(f"IPMI IP for {server} is {ip}")
            return ip
        else:
            return False
