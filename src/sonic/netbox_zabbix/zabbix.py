import functools
from pprint import pformat

from zabbix_utils import ZabbixAPI


class SonicNetboxZabbix_Zabbix:
    """
    Utils for Zabbix stuff
    """

    def __init__(self, logger, config):
        self.log = logger
        self.config = config

        # self.log.info("Logging into Zabbix")
        api = ZabbixAPI(self.config.zabbixurl)
        api.login(token=self.config.zabbixtoken)
        self.api = api

    def __del__(self):
        self.log.info("Starting SonicNetboxZabbix_Zabbix instance deletion")
        self.api.logout()
        self.log.info("Done with SonicNetboxZabbix_Zabbix instance deletion")


    @functools.cache
    def get_hosts_all(self):
        return self.api.host.get(
            selectTags=["tag", "value"],
            selectInheritedTags=["tag", "value"],
        )

    def host_update_tags(self, hostid, tags):
        response = self.api.host.update(hostid=hostid, tags=tags)
        self.log.info(f"DEBUG: response: {pformat(response)}")
        return response

    def host_update_inventory(self, hostid, inventory):
        response = self.api.host.update(hostid=hostid, inventory=inventory)
        self.log.info(f"DEBUG: response: {pformat(response)}")
        return response
