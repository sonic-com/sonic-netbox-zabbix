import configargparse
import functools
import logging
import logging.handlers
import sys

from pprint import pprint, pformat

from sonic.netbox_zabbix.zabbix import SonicNetboxZabbix_Zabbix
from sonic.netbox_zabbix.netbox import SonicNetboxZabbix_Netbox


try:
    from sonic.logger import setup_sonic_logger
except ModuleNotFoundError as err:
    pass


class SonicNetboxZabbix:
    """
    SonicNetboxZabbix class has tools for setting up hosts in Zabbix based on Netbox data.
    """

    def __init__(self):
        """Set up argument parser and load sub-commands."""
        try:
            self.config = self._parseargs()
        except Exception as e:
            print(
                "An error occured parsing config files or command-line arguments: {}".format(
                    str(e)
                )
            )
            raise

        try:
            self.log = setup_sonic_logger(
                application_name="Sonic Netbox Zabbix",
                logger_name="netbox_zabbix",
            )
        except Exception as e:
            try:
                logging.basicConfig(
                    level=logging.WARNING,
                    format="%(name)s:%(funcName)s: %(message)s",
                )
                self.log = logging.getLogger("netbox_zabbix")
                sysloghandler = logging.handlers.SysLogHandler(
                    address="/dev/log")
                sysloghandler.setLevel(logging.INFO)
                self.log.addHandler(sysloghandler)
            except Exception as e2:
                print("Unable to make logging go: {}".format(str(e)))
                raise
            # pass

        if self.config.verbose:
            self.log.setLevel(logging.INFO)
        elif self.config.quiet:
            self.log.setLevel(logging.ERROR)

        self.log.info("Starting Sonic Netbox Zabbix Sync")

        self._zabbix_login()
        self._netbox_login()

    def _parseargs(self):
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
        argparser.add("--netboxurl", "-n", required=True,
                      help="URL for netbox")
        argparser.add("--zabbixurl", "-z", required=True,
                      help="URL for zabbix")
        argparser.add("--netboxtoken", "-N", required=True,
                      help="API auth token for Netbox")
        argparser.add("--zabbixtoken", "-Z", required=True,
                      help="API auth token for Zabbix")

        return argparser.parse_args()

    def _zabbix_login(self):
        """Log into Zabbix, creating self.zabbix self"""
        self.log.info("Logging into Zabbix")
        self.zabbix = SonicNetboxZabbix_Zabbix(self.log, self.config)

    def _netbox_login(self):
        """Log into Netbox and add napi to self"""
        self.log.info("Logging into Netbox")
        self.netbox = SonicNetboxZabbix_Netbox(self.log, self.config)

    def run(self):
        """Run cli app with the given arguments."""
        self.log.info("Starting run()")

        self.log.info("Getting list of servers from Zabbix")
        zabbix_servers = self.zabbix.get_hosts_all()
        self.log.info(f"DEBUG: zabbix_servers: {pformat(zabbix_servers)}")

        self.log.info("Getting list of servers from Netbox")
        netbox_servers = self.netbox.get_hosts_active_soc_server()
        self.log.info(f"DEBUG: netbox_servers: {pformat(netbox_servers)}")


def main():
    """Run SonicNetboxZabbix cli with sys.argv from command line."""
    app = SonicNetboxZabbix()
    app.run()


if __name__ == "__main__":
    main()
