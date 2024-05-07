import pyzabbix
import pynetbox
import configargparse
import sys
import pprint
import logging
import logging.handlers

try:
   from sonic.logger import setup_sonic_logger
except ModuleNotFoundError as err:
   pass

class NetboxZabbix():
    """
    NetboxZabbix class has tools for setting up hosts in Zabbix based on Netbox data.
    """
    
    def __init__(self):
        """Set up argument parser and load sub-commands."""
        try:
            argparser = configargparse.ArgParser(
                default_config_files=["/etc/sonic/netbox-zabbix.conf", "~/.sonic-netbox-zabbix.conf", "./sonic-netbox-zabbix.conf"],
                description="Sync netbox stuff to zabbix stuff.",
            )
            
            argparser.add("-v", "--verbose", action="store_true", help="Show more logging messages")
            argparser.add("-q", "--quiet", action="store_true", help="Show fewer logging messages")
            argparser.add("--netboxurl", required=True, help="URL for netbox")
            argparser.add("--zabbixurl", required=True, help="URL for zabbix")
            argparser.add("--netboxtoken", required=True, help="API auth token for Netbox")
            argparser.add("--zabbixtoken", required=True, help="API auth token for Zabbix")

            self.config = argparser.parse_args()
        except Exception as e:
           print('An error occured parsing config files or command-line arguments: {}'.format(str(e)))
           raise

        try:
           self.log = setup_sonic_logger(
              application_name='Sonic Netbox Zabbix',
              logger_name='netbox_zabbix',
           )
        except Exception as e:
           try:
               logging.basicConfig(
                    level=logging.WARNING,
                    format='%(name)s:%(levelno)s:%(funcName)s:%(message)s',
               )
               self.log = logging.getLogger('netbox_zabbix')
               sysloghandler = logging.handlers.SysLogHandler(address = '/dev/log')
               sysloghandler.setLevel(logging.INFO)
               self.log.addHandler(sysloghandler)
           except Exception as e2:
               print('Unable to make logging go: {}'.format(str(e)))
               raise
           # pass

        if self.config.verbose:
           self.log.setLevel(logging.INFO)
        elif self.config.quiet:
           self.log.setLevel(logging.ERROR)

        self.log.info("Starting Sonic Netbox Zabbix Sync")

    def run(self, argv):
        """Run cli app with the given arguments."""
        # self.config.print_help()

def main():
   """Run NetboxZabbix cli with sys.argv from command line."""
   app = NetboxZabbix()
   app.run(sys.argv[1:])
   

if __name__ == "__main__":
    main()
