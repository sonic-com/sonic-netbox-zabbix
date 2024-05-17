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

        if 'config' not in locals() or not config:
            try:
                config = SonicNetboxZabbix._parseargs()
            except Exception as e:
                print(f"An error occured parsing config files or command-line arguments: {str(e)}")
                raise

        if 'log' not in locals() or not log:
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
        argparser.add("--netboxurl", "-n", required=True,help="URL for netbox")
        argparser.add("--zabbixurl", "-z", required=True,help="URL for zabbix")
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
                netbox_servers[name]['custom_fields']['zabbix_host_id'] = int(
                    zabbix_servers[name]['hostid'])
                netbox_servers[name].save()
            else:
                log.info(f"No such server {name} in netbox data")


    def copy_netbox_info_to_zabbix_tags(self, netbox_servers, zabbix_servers):
        for name in zabbix_servers:
            if name in netbox_servers and netbox_servers[name]:
                if 'tags' in zabbix_servers[name]:
                    tags = zabbix_servers[name]['tags']
                    log.info(f"DEBUG: tags: {pformat(tags)}")
                    new_tags = [item for item in tags if not item['tag'].startswith('netbox-')]
                    log.info(f"DEBUG: new_tags(1): {pformat(new_tags)}")
                else:
                    new_tags = []

                new_tags.append({
                    'tag': 'netbox-id',
                    'value': str(netbox_servers[name].id)
                })


                new_tags.append({
                    'tag': 'netbox-status',
                    'value': netbox_servers[name].status['value']
                })

                new_tags.append({
                    'tag': 'netbox-platform',
                    'value': netbox_servers[name].platform['slug']
                })

                new_tags.append({
                    'tag': 'netbox-site',
                    'value': netbox_servers[name].site['slug']
                })

                new_tags.append({
                    'tag': 'netbox-tenant',
                    'value': netbox_servers[name].tenant['slug']
                })

                new_tags.append({
                    'tag': 'netbox-role',
                    'value': netbox_servers[name].role['slug']
                })

                new_tags.append({
                    'tag': 'netbox-date-created',
                    'value': netbox_servers[name].created
                })

                new_tags.append({
                    'tag': 'netbox-date-last-updated',
                    'value': netbox_servers[name].last_updated
                })

                if netbox_servers[name].tags:
                    log.info(f"Updating tags for {name}")

                    for tag in netbox_servers[name].tags:
                        new_tags.append({
                            'tag': 'netbox-tag',
                            'value': tag['slug'],
                        })
                        log.info(f"DEBUG: new_tags(2): {pformat(new_tags)}")
                else:
                    log.info(f"No netbox tags for for {name}")
                    log.info(f"DEBUG: netbox_servers[name].tags {pformat(dict(netbox_servers[name].tags))}")

                if 'update_group' in netbox_servers[name].custom_fields and netbox_servers[name].custom_fields['update_group']:
                    log.info(f"Adding update_group to zabbix for {name}")

                    new_tags.append({
                        'tag': 'netbox-update-group',
                        'value': netbox_servers[name].custom_fields['update_group'],
                    })
                else:
                    log.info(f"No update_group for {name}")

                if 'maintenance_group' in netbox_servers[name].custom_fields and netbox_servers[name].custom_fields['maintenance_group']:
                    log.info(f"Adding maintenance_group to zabbix for {name}")

                    new_tags.append({
                        'tag': 'netbox-maintenance-group',
                        'value': netbox_servers[name].custom_fields['maintenance_group'],
                    })
                else:
                    log.info(f"No maintenance_group for {name}")

                if 'maintenance_window' in netbox_servers[name].custom_fields and netbox_servers[name].custom_fields['maintenance_window']:
                    log.info(f"Adding maintenance_window to zabbix for {name}")

                    new_tags.append({
                        'tag': 'netbox-maintenance-window',
                        'value': netbox_servers[name].custom_fields['maintenance_window'],
                    })
                else:
                    log.info(f"No maintenance_window for {name}")

                log.info(f"DEBUG: new_tags(2): {pformat(new_tags)}")


                self.zabbix.host_update_tags(
                    hostid=zabbix_servers[name]['hostid'],
                    tags=new_tags,
                )


            else:
                log.info(f"No such server in {name} in netbox data")

    def copy_netbox_info_to_zabbix_inventory(self, netbox_servers, zabbix_servers):
        for name in zabbix_servers:
            if name in netbox_servers and netbox_servers[name]:
                inventory = {}

                api_url = netbox_servers[name].url
                inventory['url_a'] = api_url.replace("/api/", "/")

                if inventory:
                    self.zabbix.host_update_inventory(
                        hostid = zabbix_servers[name]['hostid'],
                        inventory=inventory,
                    )
                else:
                    log.info(f"No inventory updates for {name}")

            else:
                log.info(f"No such server in {name} in netbox data")

    def run(self):
        """Run cli app with the given arguments."""
        log.info("Starting run()")

        log.info("Getting list of servers from Zabbix")
        zabbix_server_list = self.zabbix.get_hosts_all()
        # log.info(f"DEBUG: zabbix_server_list: {pformat(zabbix_server_list)}")
        log.info(f"DEBUG: zabbix_server_list[0]: {pformat(zabbix_server_list[0])}")

        zabbix_server_dict = {}
        for zabbix_server in zabbix_server_list:
            zabbix_server_name = zabbix_server['host']
            zabbix_server_dict[zabbix_server_name] = zabbix_server

        log.info("Getting list of servers from Netbox")
        netbox_server_list = self.netbox.get_hosts_active_soc_server()
        # log.info(f"DEBUG: netbox_server_list: {pformat(netbox_server_list)}")
        log.info(f"DEBUG: netbox_server_list[0]: {pformat(dict(netbox_server_list[0]))}")

        netbox_server_dict = {}
        for netbox_server in netbox_server_list:
            netbox_server_name = netbox_server['name']
            netbox_server_dict[netbox_server_name] = netbox_server

        self.copy_zabbix_hostid_to_netbox(
            zabbix_server_dict, netbox_server_dict)

        self.copy_netbox_info_to_zabbix_tags(
            netbox_server_dict, zabbix_server_dict)

        self.copy_netbox_info_to_zabbix_inventory(
            netbox_server_dict, zabbix_server_dict)

def main():
    """Run SonicNetboxZabbix cli with sys.argv from command line."""
    app = SonicNetboxZabbix()
    app.run()


if __name__ == "__main__":
    main()
