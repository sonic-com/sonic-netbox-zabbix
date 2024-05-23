import functools
import logging
import logging.handlers
import sys
from pprint import pformat, pprint

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
                print(
                    f"An error occurred parsing config files or command-line arguments: {str(e)}"
                )
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

        if config.verbose:
            log.setLevel(logging.INFO)
        elif config.quiet:
            log.setLevel(logging.ERROR)
        else:
            log.setLevel(logging.WARNING)
        self.log = log

        log.info("Starting Sonic Netbox Zabbix Sync")

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
            "-v", "--verbose", action="store_true", help="Show more logging messages"
        )
        argparser.add(
            "-q", "--quiet", action="store_true", help="Show fewer logging messages"
        )
        argparser.add("--netboxurl", "-n", required=True, help="URL for netbox")
        argparser.add("--zabbixurl", "-z", required=True, help="URL for zabbix")
        argparser.add(
            "--netboxtoken", "-N", required=True, help="API auth token for Netbox"
        )
        argparser.add(
            "--zabbixtoken", "-Z", required=True, help="API auth token for Zabbix"
        )

        return argparser.parse_args()

    def _zabbix_login(self):
        """Log into Zabbix, creating self.zabbix self"""
        log.info("Logging into Zabbix")
        self.zabbix = SonicNetboxZabbix_Zabbix(log, config)

    def _netbox_login(self):
        """Log into Netbox and add napi to self"""
        log.info("Logging into Netbox")
        self.netbox = SonicNetboxZabbix_Netbox(log, config)

    def copy_zabbix_hostid_to_netbox(self, zabbix_servers, netbox_servers):
        for name in zabbix_servers:
            if name in netbox_servers and netbox_servers[name]:
                netbox_servers[name]["custom_fields"]["zabbix_host_id"] = int(
                    zabbix_servers[name]["hostid"]
                )
                netbox_servers[name].save()
            else:
                log.info(f"No such server {name} in netbox data")

    def copy_netbox_info_to_zabbix_macros(self, netbox_servers, zabbix_servers):
        for name in zabbix_servers:
            if name in netbox_servers and netbox_servers[name]:
                log.info(f"TRACE: macros for {name}")
                srv = netbox_servers[name]

                # Pull current macros in, minus the $NETBOX. macros
                if "macros" in zabbix_servers[name]:
                    macros = zabbix_servers[name]["macros"]
                    log.info(f"DEBUG: macros(pre): {pformat(macros)}")
                    macros = [
                        item
                        for item in macros
                        if not item["macro"].startswith("{$NETBOX.")
                    ]
                else:
                    macros = []
                log.info(f"DEBUG: macros(post): {pformat(macros)}")

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

                if (
                    "update_group" in srv.custom_fields
                    and srv.custom_fields["update_group"]
                ):
                    log.info(f"Adding update_group to zabbix macro for {name}")

                    macros.append(
                        {
                            "macro": "{$NETBOX.UPDATE_GROUP}",
                            "value": srv.custom_fields["update_group"],
                        }
                    )
                else:
                    log.info(f"No update_group for {name}")

                # Actually save changes #
                if macros:
                    log.info(f"Macros for {name}: {pformat(macros)}")
                    self.zabbix.host_update_macros(
                        hostid=zabbix_servers[name]["hostid"],
                        macros=macros,
                    )
                else:
                    log.info(f"No Macros updates for {name}")

    def copy_netbox_info_to_zabbix_tags(self, netbox_servers, zabbix_servers):
        for name in zabbix_servers:
            if name in netbox_servers and netbox_servers[name]:
                log.info(f"TRACE: tags for {name}")
                srv = netbox_servers[name]
                if "tags" in zabbix_servers[name]:
                    tags = zabbix_servers[name]["tags"]
                    log.info(f"DEBUG: tags: {pformat(tags)}")
                    tags = [
                        item for item in tags if not item["tag"].startswith("netbox-")
                    ]
                else:
                    tags = []
                log.info(f"DEBUG: tags(1): {pformat(tags)}")

                if srv.status and srv.status["value"]:
                    tags.append({"tag": "netbox-status", "value": srv.status["value"]})

                if srv.platform and srv.platform["slug"]:
                    tags.append({"tag": "netbox-platform", "value": srv.platform["slug"]})

                if srv.site and srv.site["slug"]:
                    tags.append({"tag": "netbox-site", "value": srv.site["slug"]})

                if srv.tenant and srv.tenant["slug"]:
                    tags.append({"tag": "netbox-tenant", "value": srv.tenant["slug"]})

                if srv.role and srv.role["slug"]:
                    tags.append({"tag": "netbox-role", "value": srv.role["slug"]})

                if srv.tags:
                    log.info(f"Updating tags for {name}")

                    for tag in srv.tags:
                        tags.append(
                            {
                                "tag": "netbox-tag",
                                "value": tag["slug"],
                            }
                        )
                        log.info(f"DEBUG: tags(2): {pformat(tags)}")
                else:
                    log.info(f"No netbox tags for for {name}")
                    log.info(f"DEBUG: srv.tags {pformat(dict(srv.tags))}")

                if (
                    "update_group" in srv.custom_fields
                    and srv.custom_fields["update_group"]
                ):
                    log.info(f"Adding update_group to zabbix for {name}")

                    tags.append(
                        {
                            "tag": "netbox-update-group",
                            "value": srv.custom_fields["update_group"],
                        }
                    )
                else:
                    log.info(f"No update_group for {name}")

                log.info(f"DEBUG: tags(2): {pformat(tags)}")

                self.zabbix.host_update_tags(
                    hostid=zabbix_servers[name]["hostid"],
                    tags=tags,
                )

            else:
                log.info(f"No such server in {name} in netbox data")

    def copy_netbox_info_to_zabbix_inventory(self, netbox_servers, zabbix_servers):
        for name in zabbix_servers:
            if name in netbox_servers and netbox_servers[name]:
                log.info(f"TRACE: inventory for {name}")
                srv = netbox_servers[name]
                inventory = {}

                api_url = srv.url
                inventory["url_a"] = api_url.replace("/api/", "/")

                if (
                    srv.custom_fields and
                    "wiki_documentation" in srv.custom_fields
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

                if "oob_ip" in srv and len(str(srv.oob_ip)) > 1:
                    (inventory["oob_ip"], inventory["oob_netmask"]) = srv.oob_ip[
                        "address"
                    ].split("/")

                # If we did anything, update Zabbix
                if inventory:
                    log.info(f"Inventory for {name}: {pformat(inventory)}")
                    self.zabbix.host_update_inventory(
                        hostid=zabbix_servers[name]["hostid"],
                        inventory=inventory,
                    )
                else:
                    log.info(f"No inventory updates for {name}")

            else:
                log.info(f"No such server in {name} in netbox data")

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
                log.info(f"TRACE: groups for {name}")
                nbsrv = netbox_servers[name]
                zbsrv = zabbix_servers[name]
                hostgroups = zbsrv["hostgroups"]
                log.info(f"TRACE: hostgroups:unfiltered: {hostgroups}")
                hostgroups = [
                    item for item in hostgroups if not item["name"].startswith("Sites/")
                ]
                hostgroups = [
                    item for item in hostgroups if not item["name"].startswith("Sonic/")
                ]
                log.info(f"TRACE: hostgroups:filtered: {hostgroups}")
                hostgroups = [{"groupid": item["groupid"]} for item in hostgroups]

                # sites
                site = nbsrv.site
                site.full_details()
                hostgroup_path = self.site_to_path(site)
                log.info(f"DEBUG: hostgroup_path: {hostgroup_path}")
                new_hostgroup = self.zabbix.hostgroup_site_get_or_create(hostgroup_path)
                log.info(f"DEBUG:new_hostgroup{new_hostgroup}")
                hostgroups.append(new_hostgroup)

                # Tenant
                if nbsrv.tenant and nbsrv.tenant["display"]:
                    log.info(f"DEBUG: adding hostgroup {nbsrv.tenant['display']}")
                    new_hostgroup = self.zabbix.hostgroup_site_get_or_create(
                        f"Sonic/{nbsrv.tenant['display']}"
                    )
                    hostgroups.append(new_hostgroup)

                log.info(f"DEBUG: setting hostgroups: {hostgroups}")
                self.zabbix.host_update_hostgroups(zbsrv["hostid"], hostgroups)

    def run(self):
        """Run cli app with the given arguments."""
        log.info("Starting run()")

        log.info("Getting list(s) of servers from Zabbix")
        zabbix_server_list = self.zabbix.get_hosts_all()
        zabbix_notdiscovered_list = self.zabbix.get_hosts_notdiscovered()
        # log.info(f"DEBUG: zabbix_server_list: {pformat(zabbix_server_list)}")
        log.info(f"DEBUG: zabbix_server_list[0]: {pformat(zabbix_server_list[0])}")

        zabbix_server_dict = {}
        for zabbix_server in zabbix_server_list:
            if zabbix_server["host"][0].isdigit():  # UUID things like ESX hosts
                zabbix_server_name = zabbix_server["name"]
            else:
                zabbix_server_name = zabbix_server["host"]
            zabbix_server_dict[zabbix_server_name] = zabbix_server

        zabbix_notdiscovered_dict = {}
        for zabbix_server in zabbix_notdiscovered_list:
            if zabbix_server["host"][0].isdigit():  # UUID things like ESX hosts
                zabbix_server_name = zabbix_server["name"]
            else:
                zabbix_server_name = zabbix_server["host"]
            zabbix_notdiscovered_dict[zabbix_server_name] = zabbix_server

        log.info("Getting list of servers from Netbox")
        netbox_server_list = self.netbox.get_hosts_all()
        # log.info(f"DEBUG: netbox_server_list: {pformat(netbox_server_list)}")
        log.info(
            f"DEBUG: netbox_server_list[0]: {pformat(dict(netbox_server_list[0]))}"
        )

        netbox_server_dict = {}
        for netbox_server in netbox_server_list:
            netbox_server_name = netbox_server["name"]
            netbox_server_dict[netbox_server_name] = netbox_server

        self.copy_zabbix_hostid_to_netbox(zabbix_server_dict, netbox_server_dict)

        self.copy_netbox_info_to_zabbix_macros(netbox_server_dict, zabbix_server_dict)

        self.copy_netbox_info_to_zabbix_tags(netbox_server_dict, zabbix_server_dict)

        self.copy_netbox_info_to_zabbix_inventory(
            netbox_server_dict, zabbix_server_dict
        )

        self.copy_netbox_info_to_zabbix_hostgroups(
            zabbix_notdiscovered_dict, netbox_server_dict
        )


def main():
    """Run SonicNetboxZabbix cli with sys.argv from command line."""
    app = SonicNetboxZabbix()
    app.run()


if __name__ == "__main__":
    main()
