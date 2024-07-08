import functools
import logging
import logging.handlers
import sys
from pprint import pformat

import configargparse

from sonic.netbox_zabbix.netbox import SonicNetboxZabbix_Netbox
from sonic.netbox_zabbix.zabbix import SonicNetboxZabbix_Zabbix

try:
    from sonic.logger import setup_sonic_logger
except ModuleNotFoundError as err:
    pass


class SonicNetboxZabbix:
    """
    SonicNetboxZabbix class has tools for setting up hosts in Zabbix based on Netbox data.
    """

    config = False
    log = False

    def __init__(self):
        """Log in and set up."""
        global config
        global log

        if "config" not in locals() or not config:
            try:
                config = SonicNetboxZabbix._parseargs()
            except Exception as e:
                print(f"An error occurred parsing config files or command-line arguments: {str(e)}")
                raise

        if "log" not in locals() or not log:
            try:
                log = setup_sonic_logger(
                    application_name="Sonic Netbox Zabbix",
                    logger_name="netbox_zabbix",
                )
            except Exception as e:
                try:
                    logging.basicConfig(
                        level=logging.WARNING,
                        format="%(name)s:%(funcName)s: %(message)s",
                    )
                    log = logging.getLogger("netbox_zabbix")
                    sysloghandler = logging.handlers.SysLogHandler(address="/dev/log")
                    sysloghandler.setLevel(logging.INFO)
                    log.addHandler(sysloghandler)
                except Exception as e2:
                    print(f"Unable to make logging go: {str(e)}")
                    raise

        if config.verbose >= 3:
            log.setLevel(logging.DEBUG)
        elif config.verbose >= 2:
            log.setLevel(logging.INFO)
        elif config.verbose >= 1:
            log.setLevel(logging.WARNING)
        elif config.quiet:
            log.setLevel(logging.CRITICAL)
        else:
            log.setLevel(logging.ERROR)
        self.log = log

        log.debug("Starting Sonic Netbox Zabbix Sync")

        self._zabbix_login()
        self._netbox_login()

    @classmethod
    def _parseargs(cls):
        """Parse config files and CLI arguments and return a config object"""

        argparser = configargparse.ArgParser(
            default_config_files=[
                "/etc/sonic/netbox-zabbix.conf",
                "~/.sonic-netbox-zabbix.conf",
                "./sonic-netbox-zabbix.conf",
            ],
            description="Sync netbox stuff to zabbix stuff.",
        )

        argparser.add(
            "-v",
            "--verbose",
            action="count",
            default=0,
            help="Show more logging messages. More -v for more logging",
        )
        argparser.add("-q", "--quiet", action="store_true", help="Show fewer logging messages")
        argparser.add("--netboxurl", "-n", required=True, help="URL for netbox")
        argparser.add("--zabbixurl", "-z", required=True, help="URL for zabbix")
        argparser.add("--netboxtoken", "-N", required=True, help="API auth token for Netbox")
        argparser.add("--zabbixtoken", "-Z", required=True, help="API auth token for Zabbix")

        argparser.add(
            "--skip-macros",
            action="store_true",
            help="Don't update Zabbix Macros from netbox data",
        )
        argparser.add(
            "--skip-tags",
            action="store_true",
            help="Don't update Zabbix Tags from netbox data",
        )
        argparser.add(
            "--skip-inventory",
            action="store_true",
            help="Don't update Zabbix Inventory from netbox data",
        )
        argparser.add(
            "--skip-hostgroups",
            action="store_true",
            help="Don't update Zabbix Hostgroups from netbox data",
        )

        argparser.add(
            "--skip-disables",
            action="store_true",
            help="Don't disable Zabbix hosts based on netbox data",
        )

        argparser.add(
            "--skip-ipmi", action="store_true", help="Don't add IPMI interfaces to Physical Servers that have them"
        )

        return argparser.parse_args()

    def _zabbix_login(self):
        """Log into Zabbix, creating self.zabbix self"""
        log.debug("Logging into Zabbix")
        self.zabbix = SonicNetboxZabbix_Zabbix(log, config)

    def _netbox_login(self):
        """Log into Netbox and add napi to self"""
        log.debug("Logging into Netbox")
        self.netbox = SonicNetboxZabbix_Netbox(log, config)

    @staticmethod
    def copy_zabbix_hostid_to_netbox(zabbix_servers, netbox_servers):
        for name in zabbix_servers:
            if name in netbox_servers and netbox_servers[name]:
                netbox_servers[name]["custom_fields"]["zabbix_host_id"] = int(zabbix_servers[name]["hostid"])
                netbox_servers[name].save()
            else:
                log.info(f"No such server {name} in netbox data")

    def copy_netbox_info_to_zabbix_macros(self, netbox_servers, zabbix_servers):
        for name in zabbix_servers:
            if name in netbox_servers and netbox_servers[name]:
                if config.verbose >= 4:
                    log.debug(f"TRACE: macros for {name}")
                srv = netbox_servers[name]

                # Pull current macros in, minus the $NETBOX. macros
                if "macros" in zabbix_servers[name]:
                    macros = zabbix_servers[name]["macros"]
                    log.debug(f"macros(pre): {pformat(macros)}")
                    macros = [item for item in macros if not item["macro"].startswith("{$NETBOX.")]
                else:
                    macros = []
                log.debug(f"macros(post): {pformat(macros)}")

                if srv.status and srv.status["value"] and srv.status["label"]:
                    macros.append(
                        {
                            "macro": "{$NETBOX.STATUS}",
                            "value": srv.status["value"],
                            "description": srv.status["label"],
                        }
                    )

                if srv.platform and srv.platform["slug"] and srv.platform["display"]:
                    macros.append(
                        {
                            "macro": "{$NETBOX.PLATFORM}",
                            "value": srv.platform["slug"],
                            "description": srv.platform["display"],
                        }
                    )

                if srv.site and srv.site["slug"] and srv.site["display"]:
                    macros.append(
                        {
                            "macro": "{$NETBOX.SITE}",
                            "value": srv.site["slug"],
                            "description": srv.site["display"],
                        }
                    )

                if srv.tenant and srv.tenant["slug"] and srv.tenant["display"]:
                    macros.append(
                        {
                            "macro": "{$NETBOX.TENANT}",
                            "value": srv.tenant["slug"],
                            "description": srv.tenant["display"],
                        }
                    )

                if srv.role and srv.role["slug"] and srv.role["display"]:
                    macros.append(
                        {
                            "macro": "{$NETBOX.ROLE}",
                            "value": srv.role["slug"],
                            "description": srv.role["display"],
                        }
                    )

                macros.append(
                    {
                        "macro": "{$NETBOX.DATE.CREATED}",
                        "value": srv.created,
                        "description": "Date Netbox record created",
                    }
                )

                macros.append(
                    {
                        "macro": "{$NETBOX.DATE.LAST_UPDATED}",
                        "value": srv.last_updated,
                        "description": "Date Netbox record last updated",
                    }
                )

                if "update_group" in srv.custom_fields and srv.custom_fields["update_group"]:
                    log.info(f"Adding update_group to zabbix macro for {name}")

                    macros.append(
                        {
                            "macro": "{$NETBOX.UPDATE_GROUP}",
                            "value": srv.custom_fields["update_group"],
                        }
                    )
                else:
                    log.warning(f"No update_group for {name}")

                # Actually save changes #
                if macros:
                    log.debug(f"Macros for {name}: {pformat(macros)}")
                    self.zabbix.host_update_macros(
                        hostid=zabbix_servers[name]["hostid"],
                        macros=macros,
                    )
                else:
                    log.warning(f"No Macros updates for {name}")

    @staticmethod
    def add_tag_nodupe(tags, new_tag):
        if new_tag not in tags:
            tags.append(new_tag)
        return tags

    def copy_netbox_info_to_zabbix_tags(self, netbox_servers, zabbix_servers):
        for name in zabbix_servers:
            if name in netbox_servers and netbox_servers[name]:
                if config.verbose >= 4:
                    log.debug(f"TRACE: tags for {name}")
                srv = netbox_servers[name]
                if "tags" in zabbix_servers[name]:
                    tags = zabbix_servers[name]["tags"]
                    log.debug(f"{name} tags(original): {pformat(tags)}")
                    tags = [item for item in tags if not item["tag"].startswith("netbox-")]
                else:
                    tags = []
                log.debug(f"{name} tags(1): {pformat(tags)}")

                if self.netbox.is_virtual(srv) and self.netbox.virt_type(srv):
                    tags.append({"tag": "netbox-virt-type", "value": self.netbox.virt_type(srv)})

                if self.netbox.is_physical(srv) and srv.device_type and srv.device_type["slug"]:
                    tags.append({"tag": "netbox-device-type", "value": srv.device_type["slug"]})

                if srv.status and srv.status["value"]:
                    tags.append({"tag": "netbox-status", "value": srv.status["value"]})
                    # If planned, don't notify at all
                    if srv.status["value"] == "planned":
                        tags = self.add_tag_nodupe(tags, {"tag": "sonic-alerting", "value": "nonotice"})
                    # If staged, don't page
                    elif srv.status["value"] == "staged":
                        tags = self.add_tag_nodupe(tags, {"tag": "sonic-alerting", "value": "nopage"})
                    # If server is active, don't let it be nopage/nonotice unless explicitly
                    # set that way in Netbox (further down will get added back if tag is set)
                    elif srv.status["value"] == "active":
                        tags = [item for item in tags if not item["tag"] == "sonic-alerting"]

                log.debug(f"{name} tags(2): {pformat(tags)}")

                if srv.platform and srv.platform["slug"]:
                    tags.append({"tag": "netbox-platform", "value": srv.platform["slug"]})

                if srv.site and srv.site["slug"]:
                    tags.append({"tag": "netbox-site", "value": srv.site["slug"]})

                if srv.tenant and srv.tenant["slug"]:
                    tags.append({"tag": "netbox-tenant", "value": srv.tenant["slug"]})
                    if srv.tenant["slug"] == "soc-special-use":
                        tags = self.add_tag_nodupe(tags, {"tag": "sonic-alerting", "value": "nonotice"})

                if srv.role and srv.role["slug"]:
                    tags.append({"tag": "netbox-role", "value": srv.role["slug"]})

                log.debug(f"{name} tags(3): {pformat(tags)}")

                if srv.custom_fields:
                    if "zabbix_alert_routing" in srv.custom_fields and srv.custom_fields["zabbix_alert_routing"]:
                        # Remove existing sonic-alert-routing tag
                        tags = [item for item in tags if not item["tag"] == "sonic-alert-routing"]
                        tags.append(
                            {
                                "tag": "sonic-alert-routing",
                                "value": srv.custom_fields["zabbix_alert_routing"],
                            }
                        )

                if srv.tags:
                    log.info(f"{name}: Updating tags")

                    for tag in srv.tags:
                        if tag["slug"] == "zabbix-alerting-nopage" or tag["slug"] == "soc-nopage":
                            tags = self.add_tag_nodupe(tags, {"tag": "sonic-alerting", "value": "nopage"})
                        else:
                            tags.append(
                                {
                                    "tag": "netbox-tag",
                                    "value": tag["slug"],
                                }
                            )
                    log.debug(f"{name} tags(4): {pformat(tags)}")

                else:
                    log.warning(f"{name}: No netbox tags")
                    log.debug(f"{name} srv.tags {pformat(dict(srv.tags))}")

                if "update_group" in srv.custom_fields and srv.custom_fields["update_group"]:
                    log.info(f"Adding update_group to zabbix for {name}")

                    tags.append(
                        {
                            "tag": "netbox-update-group",
                            "value": srv.custom_fields["update_group"],
                        }
                    )
                else:
                    log.warning(f"{name}: No update_group for")

                log.debug(f"{name} tags(final): {pformat(tags)}")

                self.zabbix.host_update_tags(
                    hostid=zabbix_servers[name]["hostid"],
                    tags=tags,
                )

            else:
                log.warning(f"{name}: No such server in {name} in netbox data")

    def copy_netbox_info_to_zabbix_inventory(self, netbox_servers, zabbix_servers):
        for name in zabbix_servers:
            if name in netbox_servers and netbox_servers[name]:
                if config.verbose >= 4:
                    log.debug(f"TRACE:{name}: inventory")
                srv = netbox_servers[name]
                inventory = {}

                api_url = srv.url
                inventory["url_a"] = api_url.replace("/api/", "/")

                if (
                    srv.custom_fields
                    and "wiki_documentation" in srv.custom_fields
                    and srv.custom_fields["wiki_documentation"]
                ):
                    inventory["url_b"] = srv.custom_fields["wiki_documentation"]

                if srv.platform and srv.platform["slug"]:
                    inventory["os_short"] = srv.platform["slug"]
                if srv.platform and srv.platform["display"]:
                    inventory["os_full"] = srv.platform["display"]
                if srv.status and srv.status["label"]:
                    inventory["deployment_status"] = srv.status["label"]
                inventory["date_hw_install"] = srv.created

                if len(str(srv.comments)) >= 1:
                    inventory["notes"] = srv.comments

                inventory["type"] = srv.role["display"]

                if srv.site:
                    srv.site.full_details()
                    log.debug(f"Site Details: {pformat(dict(srv.site))}")
                    if "latitude" in dict(srv.site) and srv.site["latitude"]:
                        inventory["location_lat"] = srv.site["latitude"]
                    if "longitude" in dict(srv.site) and srv.site["longitude"]:
                        inventory["location_lon"] = srv.site["longitude"]

                    site_info = []

                    site_info.append(srv.site["display"])

                    if "facility" in dict(srv.site) and srv.site["facility"]:
                        site_info.append(srv.site["facility"])

                    if "group" in dict(srv.site) and srv.site["group"]:
                        site_info.append(srv.site["group"]["display"])
                    if "region" in dict(srv.site) and srv.site["region"]:
                        site_info.append(srv.site["region"]["display"])
                    if "tenant" in dict(srv.site) and srv.site["tenant"]:
                        site_info.append(srv.site["tenant"]["display"])

                    if "comments" in dict(srv.site) and srv.site["comments"]:
                        site_info.append("")
                        site_info.append(srv.site["comments"])

                    if "physical_address" in dict(srv.site) and srv.site["physical_address"]:
                        site_info.append("\nPhysical Address:")
                        site_info.append(srv.site["physical_address"])

                    if "shipping_address" in dict(srv.site) and srv.site["shipping_address"]:
                        site_info.append("\nShipping Address:")
                        site_info.append(srv.site["shipping_address"])

                    log.debug(f"site_info: {site_info}")
                    inventory["site_notes"] = "\n".join(site_info)
                if self.netbox.is_virtual(srv):
                    inventory["hardware"] = "Virtual"
                    inventory["vendor"] = self.netbox.virt_type(srv)

                if self.netbox.is_physical(srv):
                    inventory["hardware"] = "Physical"  # Discard if have better answer
                    if srv.device_type:
                        inventory["hardware"] = srv.device_type["slug"]
                        inventory["hardware_full"] = (
                            f"{srv.device_type['manufacturer']['display']} {srv.device_type['display']}"
                        )
                        inventory["vendor"] = srv.device_type["manufacturer"]["display"]
                        inventory["model"] = srv.device_type["display"]
                    if srv.rack:
                        inventory["site_rack"] = srv.rack["display"]
                    if srv.serial:
                        inventory["serialno_a"] = srv.serial
                    if srv.asset_tag:
                        inventory["asset_tag"] = srv.asset_tag

                    if srv.location:
                        srv.location.full_details()
                        log.debug(f"Location Details: {pformat(dict(srv.location))}")
                        location_info = []

                        location_info.append(srv.location["display"])

                        if "region" in dict(srv.location) and srv.location["region"]:
                            location_info.append(srv.location["region"]["display"])
                        if "site" in dict(srv.location) and srv.location["site"]:
                            location_info.append(srv.location["site"]["display"])
                        if "tenant" in dict(srv.location) and srv.location["tenant"]:
                            location_info.append(srv.location["tenant"]["display"])

                        # Potentially multi-line; put next to last
                        if "description" in dict(srv.location) and srv.location["description"]:
                            location_info.append(srv.location["description"])

                        # Likely to be multi-line; put last
                        if "physical_address" in dict(srv.location) and srv.location["physical_address"]:
                            location_info.append("\nPhysical Address:")
                            location_info.append(srv.location["physical_address"])

                        inventory["location"] = "\n".join(location_info)

                # Override if more specific on device:
                if "latitude" in dict(srv) and srv.latitude:
                    inventory["location_lat"] = srv.latitude
                if "longitude" in dict(srv) and srv.longitude:
                    inventory["location_lon"] = srv.longitude

                if "oob_ip" in srv and len(str(srv.oob_ip)) > 1:
                    (inventory["oob_ip"], inventory["oob_netmask"]) = srv.oob_ip["address"].split("/")

                # If we did anything, update Zabbix
                if inventory:
                    log.debug(f"{name}:Inventory: {pformat(inventory)}")
                    self.zabbix.host_update_inventory(
                        hostid=zabbix_servers[name]["hostid"],
                        inventory=inventory,
                    )
                else:
                    log.warning(f"{name}No inventory updates")

            else:
                log.warning(f"{name}: No such host in netbox data")

    @functools.cache
    def site_to_path(self, site) -> str:

        # region / group / provider / tenant / site

        parts = ["Sites"]

        if site.region and site.region.display:
            parts.append(site.region.display)

        # if site.group and site.group.display:
        #     parts.append(site.group.display)

        # if site.custom_fields["Provider"] and site.custom_fields["Provider"]["display"]:
        #     parts.append(site.custom_fields['Provider']['display'])

        # End of all site paths: specific site
        parts.append(site.display)

        return "/".join(parts)

    def copy_netbox_info_to_zabbix_hostgroups(self, zabbix_servers, netbox_servers):
        for name in zabbix_servers:
            if name in netbox_servers and netbox_servers[name]:
                if config.verbose >= 4:
                    log.debug(f"TRACE:{name}:groups")
                nbsrv = netbox_servers[name]
                zbsrv = zabbix_servers[name]
                hostgroups = zbsrv["hostgroups"]
                if config.verbose >= 4:
                    log.debug(f"TRACE:{name}: hostgroups:unfiltered: {hostgroups}")
                hostgroups = [item for item in hostgroups if not item["name"].startswith("Sites/")]
                hostgroups = [item for item in hostgroups if not item["name"].startswith("Sonic/")]
                hostgroups = [item for item in hostgroups if not item["name"].endswith("Physical Servers")]
                if config.verbose >= 4:
                    log.debug(f"TRACE:{name}: hostgroups:filtered: {hostgroups}")

                if any(grp["name"] == "ALL" for grp in hostgroups):
                    log.debug(f"Hostgroup ALL already present")
                else:
                    log.info(f"Adding Hostgroup ALL to {name}")
                    new_hostgroup = self.zabbix.hostgroup_get_or_create("ALL")
                    hostgroups.append(new_hostgroup)

                if self.netbox.is_physical(nbsrv):
                    log.info(f"Adding Hostgroup Physical Servers to {name}")
                    new_hostgroup = self.zabbix.hostgroup_get_or_create("Physical Servers")
                    hostgroups.append(new_hostgroup)
                else:
                    log.debug(f"Virtual Server: {name}")

                # Throw out everything but groupid:
                hostgroups = [{"groupid": item["groupid"]} for item in hostgroups]

                # sites
                site = nbsrv.site
                if site:
                    site.full_details()
                    hostgroup_path = self.site_to_path(site)
                    log.debug(f"{name}:hostgroup_path: {hostgroup_path}")
                    new_hostgroup = self.zabbix.hostgroup_get_or_create(hostgroup_path)
                    log.debug(f"{name}:new_hostgroup{new_hostgroup}")
                    hostgroups.append(new_hostgroup)
                else:
                    log.debug(f"{name}:No site?")

                # Tenant
                if nbsrv.tenant and nbsrv.tenant["display"]:
                    log.debug(f"{name}:adding hostgroup {nbsrv.tenant['display']}")
                    new_hostgroup = self.zabbix.hostgroup_get_or_create(f"Sonic/{nbsrv.tenant['display']}")
                    hostgroups.append(new_hostgroup)
                    if self.netbox.is_physical(nbsrv):
                        new_hostgroup = self.zabbix.hostgroup_get_or_create(
                            f"Sonic/{nbsrv.tenant['display']}/Physical Servers"
                        )
                        hostgroups.append(new_hostgroup)

                log.debug(f"{name}:setting hostgroups: {hostgroups}")
                self.zabbix.host_update_hostgroups(zbsrv["hostid"], hostgroups)

    def disable_enable_zabbix_hosts_from_netbox_data(self, zabbix_servers, netbox_servers):
        for name in zabbix_servers:
            if name in netbox_servers and netbox_servers[name]:
                if config.verbose >= 4:
                    log.debug(f"TRACE:{name}:disable?")
                nbsrv = netbox_servers[name]
                zbsrv = zabbix_servers[name]
                # Enable if tagged Zabbix Enable
                if any(tag["slug"] == "zabbix-enable" for tag in nbsrv.tags):
                    log.debug("Zabbix Enable Tag")
                    self.zabbix.host_enable(zbsrv)
                # Disable if tagged Zabbix Disable
                elif any(tag["slug"] == "zabbix-disable" for tag in nbsrv.tags):
                    log.debug("Zabbix Disable Tag")
                    self.zabbix.host_disable(zbsrv)
                # Disable if status is various inactive types
                elif nbsrv.status["value"] in [
                    "decommissioning",
                    "planned",
                    "inventory",
                    "failed",
                    "offline",
                ]:
                    log.debug(f"In-Active Host {name}/{nbsrv.status['value']}")
                    self.zabbix.host_disable(zbsrv)
                # Per-tenant logic
                elif nbsrv.tenant and nbsrv.tenant["slug"]:
                    # Skip "SOC Special Use" for now
                    if nbsrv.tenant["slug"] == "soc-special-use":
                        log.info(f"Skipping SOC Special Use host {name}")
                    # Enable active and staged SOC hosts
                    elif nbsrv.tenant["slug"] == "soc":
                        if nbsrv.status["value"] == "active":
                            log.debug(f"SOC Active host {name}")
                            self.zabbix.host_enable(zbsrv)
                        elif nbsrv.status["value"] == "staged":
                            log.debug(f"SOC Staged host {name}")
                            self.zabbix.host_enable(zbsrv)
                        else:
                            log.info(f"Skipping enable/disable of SOC non-active host {name}/{nbsrv.status['value']}")
                    else:
                        log.info(f"Skipping non-SOC host {name}")
                else:
                    log.warning(f"No tenant on {name}")

    def copy_netbox_ipmi_to_zabbix(self, netbox_servers, zabbix_servers):
        for name in zabbix_servers:
            if name in netbox_servers and netbox_servers[name]:
                if config.verbose >= 4:
                    log.debug(f"TRACE:{name}:IPMI")
                nbsrv = netbox_servers[name]
                zbsrv = zabbix_servers[name]
                # nbsrv.full_details()
                if config.verbose >= 3:
                    log.debug(pformat(dict(nbsrv)))

    def run(self):
        """Run cli app with the given arguments."""
        log.debug("Starting run()")

        log.debug("Getting list(s) of servers from Zabbix")
        zabbix_server_list = self.zabbix.get_hosts_all()
        zabbix_notdiscovered_list = self.zabbix.get_hosts_notdiscovered()
        if config.verbose >= 4:
            log.debug(f"zabbix_server_list: {pformat(zabbix_server_list)}")
        else:
            log.debug(f"zabbix_server_list[0]: {pformat(zabbix_server_list[0])}")

        zabbix_server_dict = {}
        for zabbix_server in zabbix_server_list:
            if zabbix_server["host"][0].isdigit():  # UUID things like ESX hosts
                zabbix_server_name = zabbix_server["name"].lower()
            else:
                zabbix_server_name = zabbix_server["host"].lower()
            zabbix_server_dict[zabbix_server_name] = zabbix_server

        zabbix_notdiscovered_dict = {}
        for zabbix_server in zabbix_notdiscovered_list:
            if zabbix_server["host"][0].isdigit():  # UUID things like ESX hosts
                zabbix_server_name = zabbix_server["name"].lower()
            else:
                zabbix_server_name = zabbix_server["host"].lower()
            zabbix_notdiscovered_dict[zabbix_server_name] = zabbix_server

        log.debug("Getting list of servers from Netbox")
        netbox_server_list = self.netbox.get_hosts_all()
        if config.verbose >= 4:
            for server in netbox_server_list:
                log.debug(f"netbox_server_N: {pformat(dict(server))}")
        else:
            log.debug(f"DEBUG: netbox_server_list[0]: {pformat(dict(netbox_server_list[0]))}")

        netbox_server_dict = {}
        for netbox_server in netbox_server_list:
            if netbox_server["name"]:
                netbox_server_name = netbox_server["name"].lower()
                netbox_server_dict[netbox_server_name] = netbox_server

        self.copy_zabbix_hostid_to_netbox(zabbix_server_dict, netbox_server_dict)

        if not config.skip_ipmi:
            self.copy_netbox_ipmi_to_zabbix(netbox_server_dict, zabbix_notdiscovered_dict)

        if not config.skip_macros:
            self.copy_netbox_info_to_zabbix_macros(netbox_server_dict, zabbix_server_dict)

        if not config.skip_tags:
            self.copy_netbox_info_to_zabbix_tags(netbox_server_dict, zabbix_server_dict)

        if not config.skip_inventory:
            self.copy_netbox_info_to_zabbix_inventory(netbox_server_dict, zabbix_server_dict)

        if not config.skip_hostgroups:
            self.copy_netbox_info_to_zabbix_hostgroups(zabbix_notdiscovered_dict, netbox_server_dict)

        if not config.skip_disables:
            self.disable_enable_zabbix_hosts_from_netbox_data(zabbix_server_dict, netbox_server_dict)


def main():
    """Run SonicNetboxZabbix cli with sys.argv from command line."""
    app = SonicNetboxZabbix()
    app.run()


if __name__ == "__main__":
    main()
