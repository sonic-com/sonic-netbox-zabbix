import pyzabbix
import pynetbox
import configargparse
import sys
import pprint

from sonic.logger import setup_sonic_logger

class NetboxZabbix():
    """
    NetboxZabbix class has tools for setting up hosts in Zabbix based on Netbox data.
    """
    
    def __init__(self):
        """Set up argument parser and load sub-commands."""
        epilog = """
               General Options:
                 -h, --help           Show this help message and exit
                 -v, --verbose        Show more logging messages
                 -q, --quiet          Show fewer logging messages"""
        try:
            self.config = configargparse.ArgParser(
                default_config_files=["/etc/sonic/netbox-zabbix.conf", "~/.sonic-netbox-zabbix.conf"],
                description="Sync netbox stuff to zabbix stuff.",
                epilog=epilog,
            )
        except Exception as e:
           print('An error occured parsing config files or command-line arguments: {}'.format(str(e)))

        try:
           self.logger = setup_sonic_logger(
              application_name='Sonic Netbox Zabbix',
              logger_name='netbox_zabbix',
           )
           self.logger.info("Starting Sonic Netbox Zabbix Sync")
        except Exception as e:
           print('An error occured setting up logging: {}'.format(str(e)))
           

    def run(self, argv):
        """Run cli app with the given arguments."""
        self.config.print_help()

def main():
   """Run NetboxZabbix cli with sys.argv from command line."""
   app = NetboxZabbix()
   app.run(sys.argv[1:])
   

if __name__ == "__main__":
    main()
