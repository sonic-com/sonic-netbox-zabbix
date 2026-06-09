"""Command-line entry point: argument parsing, logging setup, and ``main``."""

import logging
import logging.handlers

import configargparse


def parse_args():
    """Parse config files and CLI arguments and return a config object."""

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
        "--skip-services",
        action="store_true",
        help="Don't update Zabbix ports macros from netbox service data",
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
        "--skip-creates",
        action="store_true",
        help="Don't create Zabbix hosts based on netbox data",
    )
    argparser.add(
        "--skip-ipmi",
        action="store_true",
        help="Don't add IPMI interfaces to Physical Devices that have them",
    )

    return argparser.parse_args()


def setup_logging(config):
    """Configure and return the ``netbox_zabbix`` logger from parsed config."""
    logging.basicConfig(
        level=logging.WARNING,
        format="%(name)s:%(funcName)s: %(message)s",
    )
    log = logging.getLogger("netbox_zabbix")

    try:
        sysloghandler = logging.handlers.SysLogHandler(address="/dev/log")
        sysloghandler.setLevel(logging.INFO)
        log.addHandler(sysloghandler)
    except OSError:
        # /dev/log isn't available everywhere (e.g. dev laptops); fall back to
        # the console handler configured by basicConfig above.
        log.debug("Syslog socket /dev/log unavailable; logging to console only")

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

    return log


def main():
    """Run SonicNetboxZabbix CLI with sys.argv from the command line."""
    # Imported lazily to avoid a circular import (sync imports from cli).
    from netbox_zabbix.sync import SonicNetboxZabbix

    app = SonicNetboxZabbix()
    app.run()
